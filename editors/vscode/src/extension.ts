import { ExtensionContext, workspace } from "vscode";
import {
  Executable,
  LanguageClient,
  LanguageClientOptions,
} from "vscode-languageclient/node";

let client: LanguageClient;

export function activate(_context: ExtensionContext) {
  console.log("YARA vscode initialization");

  workspace.onDidChangeConfiguration((event) => {
    const langServerAffected = event.affectsConfiguration("yls.executablePath");
    if (langServerAffected) {
      restartLanguageClient();
    }
  });

  restartLanguageClient();
}

async function restartLanguageClient(): Promise<void> {
  console.log("Restarting language client");

  // Deactivate previously launched client.
  deactivate();

  // Get the editor configuration
  const config = workspace.getConfiguration("yls");
  console.log("YLS configuration ", config);

  const execPath: string =
    process.env.YLS_EXECUTABLE_PATH || config.get("executablePath") || "yls";
  const execArgs: string[] = ["-vv"];

  console.log("Exec path: ", execPath);
  console.log("Exec args: ", execArgs);

  // Configure how to start the server
  const serverExecutable: Executable = {
    command: execPath,
    args: execArgs,
  };

  // Register the server for yara files
  const clientOptions: LanguageClientOptions = {
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
  await client.start();
}

export function deactivate(): Promise<void> | undefined {
  if (!client) {
    return undefined;
  }
  return client.stop();
}
