#:project ../AotSmoke.csproj

// AC-12, file-based-app leg (issue #27). `dotnet run tasks/aot-smoke/file-based-app/aot-smoke.cs -- emit <report.json>`
// runs the same paths as the AotSmoke project inside a .NET 10 file-based app, which applies the SDK's
// native-AOT defaults (PublishAot, reflection-based serialization disabled) even under `dotnet run`.
// Its report must match the other legs byte for byte.
return await DataProofsDotnet.Tools.AotSmoke.SmokeMain.RunAsync(args);
