import { ExtensionContext, workspace } from "vscode";
import {
  Executable,
  LanguageClient,
  LanguageClientOptions,
} from "vscode-languageclient/node";

let client: LanguageClient;

export function activate(_context: ExtensionContext) {
  console.log("YARA vscode initialization");

  // Get the editor configuration
  const config = workspace.getConfiguration("yara");
  console.log("YLS configuration ", config);

  let execPath: string =
    process.env.YLS_EXECUTABLE_PATH ||
    config.get("yls.executable_path") ||
    "yls";
  let execArgs: Array<string> = ["-vv"];

  console.log("Exec path: ", execPath);
  console.log("Exec args: ", execArgs);

  // Configure how to start the server
  const serverExecutable: Executable = {
    command: execPath,
    args: execArgs,
  };

  // Register the server for yara files
  let clientOptions: LanguageClientOptions = {
    documentSelector: [{ scheme: "file", language: "yara" }],
  };

  // Create the language client and start the client
  client = new LanguageClient(
    "yls",
    "Yara Language Server",
    serverExecutable,
    clientOptions
  );

  // Start the client. This will also launch the server
  client.start();
}

export function deactivate(): Promise<void> | undefined {
  if (!client) {
    return undefined;
  }
  return client.stop();
}
