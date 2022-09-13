import { commands, ExtensionContext, window, workspace } from "vscode";
import {
  Executable,
  LanguageClient,
  LanguageClientOptions,
} from "vscode-languageclient/node";

let client: LanguageClient;

export function activate(_context: ExtensionContext) {
  console.log("YARA vscode initialization");

  workspace.onDidChangeConfiguration(event => {
    let langServerAffected = event.affectsConfiguration("yls.executablePath");
    if (langServerAffected)
      restartLanguageClient();

    let sampleDirAffected = event.affectsConfiguration("yls.yari.samplesDirectory");
    if (sampleDirAffected)
      updateSamplesDirectory();
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

  let execPath: string =
    process.env.YLS_EXECUTABLE_PATH ||
    config.get("executablePath") ||
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
  await client.start();
  window.showInformationMessage("New instance of YLS has been launched");

  // After each restart we have to set the current sample directory for the new client
  updateSamplesDirectory();
}

function updateSamplesDirectory(): void {
  let dir_path = workspace.getConfiguration("yls.yari").get("samplesDirectory");
  console.log("Local samples directory changed: ", dir_path);
  commands.executeCommand("yls.eval_set_samples_dir", dir_path);
}

export function deactivate(): Promise<void> | undefined {
  if (!client) {
    return undefined;
  }
  return client.stop();
}
