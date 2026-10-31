/*
// <copyright>
// dotNetRDF is free and open source software licensed under the MIT License
// -------------------------------------------------------------------------
// 
// Copyright (c) 2009-2026 dotNetRDF Project (http://dotnetrdf.org/)
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is furnished
// to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
// WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
// </copyright>
*/

// dotNetRDF is free and open source software licensed under the MIT License
//
// -----------------------------------------------------------------------------
//
// Copyright (c) [InvalidReference] dotNetRDF Project
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is furnished
// to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
// WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

// ---------------------------------------------------------------------------------------------------
// Copied from dotNetRDF 3.5.1, Libraries/dotNetRdf.Core/Core/RdfCanonicalizer.cs (tag v3.5.1), under the
// MIT licence above, because dotNetRDF's own class deviates from RDFC-1.0 (dotnetrdf/dotnetrdf#917) and
// its private members cannot be patched from outside. Apart from the namespace, usings and accessibility,
// every difference from that file is marked "DataProofsDotnet:". Three are the fixes, some are the work
// and depth limits the fixes need, and the rest are needed to build inside this package.
//
// DELETE THIS FILE once a dotNetRDF release fixes #917: RdfCanonicalizationDeviationTests fails when an
// upgrade does, and RdfCanonicalizationDifferentialTests then proves the upstream class is enough.
// ---------------------------------------------------------------------------------------------------

#nullable disable

using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using NetCrypto;
using VDS.RDF;
using VDS.RDF.JsonLd;
using VDS.RDF.JsonLd.Processors;
using VDS.RDF.Writing.Formatting;

namespace DataProofsDotnet.Rdfc.Internal;

/// <summary>
/// Implementation of the RDFC-1.0 algorithm. Transforms a RDF graph into its canonical form.
/// </summary>
/// <param name="hashAlgorithm"></param>
// DataProofsDotnet: internal, renamed, and takes this package's hash enum.
internal sealed class Rdfc10Canonicalizer(RdfCanonicalizationHashAlgorithm hashAlgorithm)
{
    private const string CanonicalIdentifier = "c14n";
    private readonly BlankNodeGenerator _canonicalIssuer = new(CanonicalIdentifier);
    private readonly MultiValueDictionary<string, Quad> _blankNodeToQuadsMap = new();
    private readonly MultiValueDictionary<string, string> _hashToBlankNodesMap = new();
    private readonly RdfCanonicalizationHashAlgorithm _hashAlgorithm = hashAlgorithm;
    // DataProofsDotnet: the work limit. Upstream allows 1,000 N-degree walks, which its defect kept low:
    // walks from already-labelled nodes issued every tied node at once. Done as specified, a chain of like
    // nodes as deep as JSON input allows (64 levels) costs about the square of its length, so 1,000 would
    // refuse it. The budget therefore grows, and is spent per related node as well as per walk, so that
    // a node with many neighbours (the W3C poison graph, a large clique) pays for what it costs. It is set in
    // Canonicalize: a fixed amount plus a term linear in the document, which keeps large flat documents.
    // Permutations spend it too, and so does the cost that does not show in a count: copying a large issuer
    // and hashing a long predicate. Without those a hostile document of a few hundred bytes could take
    // minutes, because a permutation that recursed into nothing cost nothing.
    private const int BaseWorkBudget = 20_000;
    private const int WorkBudgetPerBlankNode = 4;
    private const int IssuerEntriesPerWorkUnit = 256;
    private const int HashedCharactersPerWorkUnit = 1024;
    private int _nquadsRecursionLimit;

    // DataProofsDotnet: the old limit also bounded recursion depth. A chain of tied blank nodes, which N-Quads
    // or explicit JSON-LD identifiers can make arbitrarily long, recurses once per node, and a stack overflow
    // cannot be caught. So depth has its own limit, upstream's effective one, and
    // EnsureSufficientExecutionStack refuses in time on a smaller stack.
    private const int MaxNquadsDepth = 1000;
    private int _nquadsDepth;

    // DataProofsDotnet: first-degree hashes never change, and upstream recomputed one for every related node
    // on every walk, which made a hostile clique cost the cube of its size. rdf-canonize keeps them too.
    private readonly Dictionary<string, string> _firstDegreeHashes = [];

    /// <summary>
    /// This implements RDFC-1.0 (https://www.w3.org/TR/rdf-canon).
    /// </summary>
    /// <param name="inputDataset"></param>
    /// <returns></returns>
    public CanonicalizedRdfDataset Canonicalize(ITripleStore inputDataset)
    {
        // 1) Create the canonicalization state (done in constructor).
        // Note: Since our input will always be a dataset, we do not need to parse n-quads syntax.

        var outputDataset = new TripleStore();
        var inputDatasetEnum = inputDataset.Graphs.ToList();

        // 2) For every quad (generated here using LINQ) in the input dataset
        // 2.1) For every blank node of the quad, add an entry to _blankNodeToQuadsMap linking them
        inputDatasetEnum.SelectMany(graph =>
                graph.Triples.SelectMany(triple =>
                    // DataProofsDotnet: Distinct, so a quad that names a blank node twice (a self-reference) is listed
                    // once, as the specification's quad set requires (dotnetrdf/dotnetrdf#917).
                    triple.Nodes.Concat([graph.Name]).OfType<BlankNode>().Distinct().Select(node => (graph, triple, node))))
            .ToList().ForEach(item =>
                _blankNodeToQuadsMap.Add(item.node.InternalID, new Quad(item.triple, item.graph.Name)));

        // 3) For each key in _blankNodeToQuadsMap
        foreach (var identifier in _blankNodeToQuadsMap.Keys.ToList())
        {
            // 3.1) Create a hash using HashFirstDegreeQuads
            var hash = HashFirstDegreeQuads(identifier);
            // 3.2) Add the an entry to _hashToBlankNodesMap
            _hashToBlankNodesMap.Add(hash, identifier);
        }

        // DataProofsDotnet: see BaseWorkBudget.
        _nquadsRecursionLimit = BaseWorkBudget + (WorkBudgetPerBlankNode * _blankNodeToQuadsMap.Keys.Count());

        // 4) For each entry of _hashToBlankNodesMap, code point ordered by hash
        // 4.1) Skipping entries that have more than one value
        foreach (KeyValuePair<string, List<string>> entry in _hashToBlankNodesMap
                     .OrderBy(p => p.Key, StringComparer.Ordinal).Where(pair => pair.Value.Count <= 1))
        {
            // 4.2) Issue a canonical identifier for the blank node
            _canonicalIssuer.GenerateBlankNodeIdentifier(entry.Value[0]);
            // 4.3) Remove the entry from _hashToBlankNodesMap
            // DataProofsDotnet: the map is keyed by hash. Removing by entry.Value[0], a blank node identifier,
            // removed nothing, so step 5 walked nodes that already had a canonical identifier and their
            // walks issued their tied neighbours' identifiers in traversal order (dotnetrdf/dotnetrdf#917).
            _hashToBlankNodesMap.Remove(entry.Key);
        }

        // 5) For each entry of _hashToBlankNodesMap, code point ordered by hash 
        foreach (KeyValuePair<string, List<string>> entry in _hashToBlankNodesMap.OrderBy(p => p.Key,
                     StringComparer.Ordinal))
        {
            // 5.1) Create hashPathList where each item will be a result of running HashNDegreeQuads
            var hashPathList = new List<(string hash, IBlankNodeGenerator issuer)>();

            // 5.2) For each blank node identifier in the map entry 
            foreach (var blankNodeIdentifier in entry.Value)
            {
                // 5.2.1) If a canonical identifier has already been issued, continue to the next blank node identifier
                // DataProofsDotnet: ask the issuer. The identifier here is the input label, which never
                // starts with the canonical prefix, so the test never skipped (dotnetrdf/dotnetrdf#917).
                if (_canonicalIssuer.GetMappedIdentifier(blankNodeIdentifier) != null) continue;
                // 5.2.2) Create temporary issuer, an identifier issuer initialized with the prefix 'b' (the default)
                var tempIssuer = new BlankNodeGenerator();
                // 5.2.3) Generate a temporary blank node identifier using tempIssuer
                tempIssuer.GenerateBlankNodeIdentifier(blankNodeIdentifier);
                // 5.2.4) Run HashNDegreeQuads for the blank node identifier, passing the other variables we just set up
                hashPathList.Add((
                    HashNDegreeQuads(blankNodeIdentifier, tempIssuer, out IBlankNodeGenerator resultIssuer),
                    resultIssuer));
            }

            // 5.3) For each entry of hashPathList, code point ordered by the hash
            // 5.3.1a) For each blank node identifier issued by the temporary identifier (aggregated here using LINQ)
            foreach (var identifier in hashPathList.OrderBy(p => p.hash, StringComparer.Ordinal)
                         .SelectMany(result => result.issuer.GetMappedIdentifiers()))
            {
                // 5.3.1b) generate a canonical identifier
                _canonicalIssuer.GenerateBlankNodeIdentifier(identifier);
            }
        }

        // Generate the canonicalized dataset
        foreach (IGraph graph in inputDatasetEnum)
        {
            IRefNode graphName = graph.Name is BlankNode graphBlankNode
                ? new BlankNode(_canonicalIssuer.GenerateBlankNodeIdentifier(graphBlankNode.InternalID).Substring(2))
                : graph.Name;

            var nGraph = new Graph(graphName);
            foreach (Triple triple in graph.Triples)
            {
                INode subj = triple.Subject is BlankNode subjBlankNode
                    ? new BlankNode(_canonicalIssuer.GenerateBlankNodeIdentifier(subjBlankNode.InternalID).Substring(2))
                    : triple.Subject;

                INode pred = triple.Predicate is BlankNode predBlankNode
                    ? new BlankNode(_canonicalIssuer.GenerateBlankNodeIdentifier(predBlankNode.InternalID).Substring(2))
                    : triple.Predicate;

                INode obj = triple.Object is BlankNode objBlankNode
                    ? new BlankNode(_canonicalIssuer.GenerateBlankNodeIdentifier(objBlankNode.InternalID).Substring(2))
                    : triple.Object;

                var nTriple = new Triple(subj, pred, obj);
                // DataProofsDotnet: Triples.Add is not accessible outside dotNetRDF.
                nGraph.Assert(nTriple);
            }

            outputDataset.Add(nGraph, true);
        }

        return new CanonicalizedRdfDataset(inputDataset, outputDataset, _canonicalIssuer.GetDictionary());
    }

    private string HashFirstDegreeQuads(string identifier)
    {
        // DataProofsDotnet: see _firstDegreeHashes.
        if (_firstDegreeHashes.TryGetValue(identifier, out var known)) return known;

        var formatter = new NQuads11Formatter();

        IOrderedEnumerable<string> nquads = _blankNodeToQuadsMap[identifier]
            .Select(quad => PrepareQuadForHash(quad, identifier))
            .Select(quad => formatter.Format(quad.Triple, quad.Graph) + '\n')
            .OrderBy(p => p, StringComparer.Ordinal);

        return _firstDegreeHashes[identifier] = MultiHash(nquads); // DataProofsDotnet: see _firstDegreeHashes.
    }

    private string HashNDegreeQuads(string identifier, IBlankNodeGenerator issuer, out IBlankNodeGenerator issuerResult)
    {
        if (_nquadsRecursionLimit-- <= 0) throw new Exception("Recursion limit reached");
        // DataProofsDotnet: see MaxNquadsDepth. A throw abandons the whole canonicalization, so the
        // matching decrement at the end of this method needs no finally.
        if (++_nquadsDepth > MaxNquadsDepth) throw new Exception("Recursion depth limit reached");
        RuntimeHelpers.EnsureSufficientExecutionStack();

        var relatedHashToBlankNodesMap = new MultiValueDictionary<string, string>();
        foreach (Quad quad in _blankNodeToQuadsMap[identifier])
        {
            ProcessRelatedComponent(quad.Subject, "s", identifier, quad, issuer, ref relatedHashToBlankNodesMap);
            ProcessRelatedComponent(quad.Object, "o", identifier, quad, issuer, ref relatedHashToBlankNodesMap);
            ProcessRelatedComponent(quad.Graph, "g", identifier, quad, issuer, ref relatedHashToBlankNodesMap);
        }

        List<string> dataToHash = [];

        foreach (KeyValuePair<string, List<string>> mapping in relatedHashToBlankNodesMap.OrderBy(p => p.Key,
                     StringComparer.Ordinal))
        {
            dataToHash.Add(mapping.Key);
            var chosenPath = string.Empty;
            IBlankNodeGenerator chosenIssuer = null;

            var firstPermutation = true; // DataProofsDotnet: see BaseWorkBudget. Walks already pay for the first.
            foreach (IList<string> permutation in PermutationsWithinBudget(mapping.Value))
            {
                if (!firstPermutation && _nquadsRecursionLimit-- <= 0) throw new Exception("Recursion limit reached");
                firstPermutation = false;
                _nquadsRecursionLimit -= issuer.GetDictionary().Count / IssuerEntriesPerWorkUnit;

                IBlankNodeGenerator issuerCopy = issuer.Clone();
                var path = string.Empty;
                var recursionList = new List<string>();

                foreach (var related in permutation)
                {
                    var canonicalId = _canonicalIssuer.GetMappedIdentifier(related);
                    if (canonicalId != null)
                    {
                        path += canonicalId;
                    }
                    else
                    {
                        if (issuerCopy.GetMappedIdentifier(related) == null)
                            recursionList.Add(related);
                        path += issuerCopy.GenerateBlankNodeIdentifier(related);
                    }

                    if (!string.IsNullOrEmpty(chosenPath) && path.Length >= chosenPath.Length &&
                        StringGreaterThan(path, chosenPath))
                    {
                        goto nextPerm;
                    }
                }

                foreach (var related in recursionList)
                {
                    var result = HashNDegreeQuads(related, issuerCopy, out IBlankNodeGenerator issuerCopyRecurse);
                    path += issuerCopy.GenerateBlankNodeIdentifier(related);
                    path += $"<{result}>";
                    issuerCopy = issuerCopyRecurse;
                    if (!string.IsNullOrEmpty(chosenPath) && path.Length >= chosenPath.Length &&
                        StringGreaterThan(path, chosenPath))
                    {
                        goto nextPerm;
                    }
                }

                if (!string.IsNullOrEmpty(chosenPath) && !StringLessThan(path, chosenPath))
                    continue;

                chosenPath = path;
                chosenIssuer = issuerCopy;

                nextPerm: ;
            }

            dataToHash.Add(chosenPath);
            issuer = chosenIssuer;
        }

        issuerResult = issuer;
        _nquadsDepth--; // DataProofsDotnet: see MaxNquadsDepth.
        return MultiHash(dataToHash);
    }

    private static bool StringGreaterThan(string a, string b) => StringCompare(a, b) > 0;
    private static bool StringLessThan(string a, string b) => StringCompare(a, b) < 0;

    private static int StringCompare(string a, string b) => StringComparer.Ordinal.Compare(a, b);

    private void ProcessRelatedComponent(INode node, string position, string identifier, Quad quad,
        IBlankNodeGenerator issuer,
        ref MultiValueDictionary<string, string> hashToRelatedBlankNodesMap)
    {
        if (node is not IBlankNode blankNode) return;
        if (blankNode.InternalID == identifier) return;

        // DataProofsDotnet: each related node spends the work budget too (see BaseWorkBudget).
        if (_nquadsRecursionLimit-- <= 0) throw new Exception("Recursion limit reached");

        var hash = HashRelatedBlankNode(blankNode.InternalID, quad, issuer, position);
        hashToRelatedBlankNodesMap.Add(hash, blankNode.InternalID);
    }

    private string HashRelatedBlankNode(string relatedBlankNodeIdentifier, Quad quad,
        IBlankNodeGenerator issuer, string position)
    {
        var identifier = _canonicalIssuer.GetMappedIdentifier(relatedBlankNodeIdentifier) ??
                         issuer.GetMappedIdentifier(relatedBlankNodeIdentifier) ??
                         HashFirstDegreeQuads(relatedBlankNodeIdentifier);

        var input = position;
        // DataProofsDotnet: the predicate as written. ToString() is Uri.AbsoluteUri, which percent-encodes a
        // non-ASCII IRI, so such a predicate hashed differently from the specification's <predicate>.
        // ExactIriStoreHandler has already refused any IRI whose printed form differs from this one.
        if (position != "g") input += $"<{(quad.Predicate is IUriNode predicate ? predicate.Uri.OriginalString : quad.Predicate.ToString())}>";
        input += identifier;
        _nquadsRecursionLimit -= input.Length / HashedCharactersPerWorkUnit; // DataProofsDotnet: see BaseWorkBudget.

        return MultiHash([input]);
    }

    private string MultiHash(IEnumerable<string> inputs)
    {
        // DataProofsDotnet: hashes through NetCrypto (AC-6 bans BCL hashing in src), over the same bytes.
        var data = Encoding.UTF8.GetBytes(string.Concat(inputs));
        var digest = _hashAlgorithm == RdfCanonicalizationHashAlgorithm.Sha384 ? Hash.Sha384(data) : Hash.Sha256(data);

        var hashBuilder = new StringBuilder();
        foreach (var b in digest)
            hashBuilder.Append(b.ToString("x2"));

        return hashBuilder.ToString();
    }

    private static Quad PrepareQuadForHash(Quad quad, string referenceId)
    {
        IRefNode graph = quad.Graph is BlankNode blankRefNode
            ? new BlankNode(blankRefNode.InternalID == referenceId ? "a" : "z")
            : quad.Graph;

        INode subj = quad.Subject is BlankNode blankSubjectNode
            ? new BlankNode(blankSubjectNode.InternalID == referenceId ? "a" : "z")
            : quad.Subject;

        INode pred = quad.Predicate is BlankNode blankPredicateNode
            ? new BlankNode(blankPredicateNode.InternalID == referenceId ? "a" : "z")
            : quad.Predicate;

        INode obj = quad.Object is BlankNode blankObjectNode
            ? new BlankNode(blankObjectNode.InternalID == referenceId ? "a" : "z")
            : quad.Object;

        return new Quad(new Triple(subj, pred, obj), graph);
    }

    private class MultiValueDictionary<TKey, TValue> : IEnumerable<KeyValuePair<TKey, List<TValue>>>
        where TKey : notnull
    {
        private readonly Dictionary<TKey, List<TValue>> _dictionary = [];

        public void Add(TKey key, TValue value)
        {
            if (_dictionary.TryGetValue(key, out List<TValue> list))
            {
                list.Add(value);
            }
            else
            {
                _dictionary.Add(key, [value]);
            }
        }

        public IEnumerable<TValue> this[TKey key] => _dictionary[key];
        public IEnumerable<TKey> Keys => _dictionary.Keys;
        public IEnumerable<TValue> Values => _dictionary.Values.SelectMany(p => p);

        IEnumerator<KeyValuePair<TKey, List<TValue>>> IEnumerable<KeyValuePair<TKey, List<TValue>>>.GetEnumerator() =>
            _dictionary.GetEnumerator();

        IEnumerator IEnumerable.GetEnumerator() => _dictionary.GetEnumerator();

        public void Clear() => _dictionary.Clear();
        public void Remove(TKey key) => _dictionary.Remove(key);
    }

    private class Quad(Triple triple, IRefNode graph)
    {
        internal readonly INode Subject = triple.Subject;
        internal readonly INode Predicate = triple.Predicate;
        internal readonly INode Object = triple.Object;
        internal readonly IRefNode Graph = graph;
        internal Triple Triple => new(Subject, Predicate, Object);
    }

    private static void RotateRight<T>(IList<T> sequence, int count)
    {
        T tmp = sequence[count - 1];
        sequence.RemoveAt(count - 1);
        sequence.Insert(0, tmp);
    }

    // DataProofsDotnet: a list naming one node repeatedly has one permutation; a repeat across graphs made
    // upstream try all n! of them. A list with more permutations than the budget can pay for is refused here,
    // before any is tried. That also keeps n small enough for Permute, which recurses n levels: a blank node
    // with 10,000 related nodes overflowed the stack, and a stack overflow cannot be caught.
    private IEnumerable<IList<string>> PermutationsWithinBudget(List<string> related)
    {
        if (related.TrueForAll(node => node == related[0]))
        {
            return [related];
        }

        double permutations = 1;
        for (var i = 2; i <= related.Count && permutations <= _nquadsRecursionLimit; i++)
        {
            permutations *= i;
        }

        if (permutations > _nquadsRecursionLimit) throw new Exception("Recursion limit reached");
        return Permute(related);
    }

    private static IEnumerable<IList<T>> Permute<T>(IList<T> sequence) => Permute(sequence, sequence.Count);

    private static IEnumerable<IList<T>> Permute<T>(IList<T> sequence, int count)
    {
        if (count == 1) yield return sequence;
        else
        {
            for (var i = 0; i < count; i++)
            {
                foreach (IList<T> perm in Permute(sequence, count - 1))
                    yield return perm;
                RotateRight(sequence, count);
            }
        }
    }

    /// <summary>
    /// A canonicalized RDF dataset, as per https://www.w3.org/TR/rdf-canon/#dfn-canonicalized-dataset.
    /// It does not contain the input blank node identifier map, as n-quads inputs are not currently supported.
    /// </summary>
    /// <remarks>
    /// For convenience, this also contains the serialized n-quads format, as well as the output dataset.
    /// </remarks>
    /// <param name="inputDataset"></param>
    /// <param name="outputDataset"></param>
    /// <param name="issuedIdentifiersMap"></param>
    internal sealed class CanonicalizedRdfDataset(
        ITripleStore inputDataset,
        ITripleStore outputDataset,
        IDictionary<string, string> issuedIdentifiersMap)
    {
        /// <summary>
        /// The dataset, serialized in canonical n-quads form.
        /// </summary>
        public string SerializedNQuads
        {
            get
            {
                var sb = new StringBuilder();
                // DataProofsDotnet: dotNetRDF's formatter is quadratic in blank nodes; see the class.
                var formatter = new DirectLabelNQuadsFormatter();
                OutputDataset.Graphs
                    .SelectMany(graph => graph.Triples.Select(triple => formatter.Format(triple, graph.Name)))
                    .OrderBy(p => p, StringComparer.Ordinal).ToList().ForEach(s =>
                    {
                        sb.Append(s);
                        sb.Append("\n");
                    });
                return sb.ToString();
            }
        }

        /// <summary>
        /// The input dataset.
        /// </summary>
        public readonly ITripleStore InputDataset = inputDataset;

        /// <summary>
        /// The canonicalized output dataset.
        /// </summary>
        public readonly ITripleStore OutputDataset = outputDataset;

        /// <summary>
        /// The mapping between original blank node identifiers and their canonical counterparts.
        /// </summary>
        public readonly IDictionary<string, string> IssuedIdentifiersMap = issuedIdentifiersMap;
    }
    
}