import * as vscode from 'vscode';
import * as cp from 'child_process';
import * as path from 'path';

let outputChannel: vscode.OutputChannel;
let currentProcess: cp.ChildProcess | null = null;

function getConfig() {
    const config = vscode.workspace.getConfiguration('veltrix');
    return {
        binaryPath: config.get<string>('binaryPath', 'veltrix'),
        apiEndpoint: config.get<string>('apiEndpoint', 'http://127.0.0.1:8080'),
    };
}

function runVeltrix(args: string[], callback?: (code: number | null) => void) {
    if (currentProcess) {
        vscode.window.showWarningMessage('An attack is already running. Stop it first.');
        return;
    }

    const { binaryPath } = getConfig();
    outputChannel.clear();
    outputChannel.show(true);

    outputChannel.appendLine(`$ ${binaryPath} ${args.join(' ')}`);

    currentProcess = cp.spawn(binaryPath, args, { shell: true });

    currentProcess.stdout?.on('data', (data: Buffer) => {
        outputChannel.append(data.toString());
    });

    currentProcess.stderr?.on('data', (data: Buffer) => {
        outputChannel.append(data.toString());
    });

    currentProcess.on('close', (code) => {
        outputChannel.appendLine(`\n[Process exited with code ${code}]`);
        currentProcess = null;
        if (callback) callback(code);
    });

    currentProcess.on('error', (err) => {
        vscode.window.showErrorMessage(`Failed to start veltrix: ${err.message}`);
        currentProcess = null;
    });
}

async function promptAttack() {
    const target = await vscode.window.showInputBox({
        prompt: 'Target (host:port)',
        placeHolder: '192.168.1.1:22',
    });
    if (!target) return;

    const protocol = await vscode.window.showQuickPick(
        ['ssh', 'ftp', 'telnet', 'smtp', 'pop3', 'rdp', 'mysql', 'postgres', 'http', 'redis'],
        { placeHolder: 'Select protocol' }
    );
    if (!protocol) return;

    const users = await vscode.window.showInputBox({
        prompt: 'Usernames (comma-separated)',
        placeHolder: 'admin,root,user',
    });
    if (!users) return;

    const passwords = await vscode.window.showInputBox({
        prompt: 'Passwords (comma-separated)',
        placeHolder: 'password,123456,admin',
    });
    if (!passwords) return;

    const userList = users.split(',').map(u => u.trim()).filter(Boolean);
    const passList = passwords.split(',').map(p => p.trim()).filter(Boolean);

    const userFile = path.join(vscode.workspace.rootPath || '.', '.veltrix-users.tmp');
    const passFile = path.join(vscode.workspace.rootPath || '.', '.veltrix-passwords.tmp');

    require('fs').writeFileSync(userFile, userList.join('\n'));
    require('fs').writeFileSync(passFile, passList.join('\n'));

    runVeltrix(['-t', target, '-P', protocol, '-U', userFile, '-W', passFile, '-o', 'veltrix-results.json', '-f', 'json'], () => {
        require('fs').unlinkSync(userFile);
        require('fs').unlinkSync(passFile);
    });
}

export function activate(context: vscode.ExtensionContext) {
    outputChannel = vscode.window.createOutputChannel('Veltrix');

    context.subscriptions.push(
        vscode.commands.registerCommand('veltrix.runAttack', async () => {
            await promptAttack();
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('veltrix.openResults', () => {
            const resultsPath = path.join(vscode.workspace.rootPath || '.', 'veltrix-results.json');
            if (require('fs').existsSync(resultsPath)) {
                vscode.workspace.openTextDocument(resultsPath).then(doc => {
                    vscode.window.showTextDocument(doc);
                });
            } else {
                vscode.window.showWarningMessage('No results file found. Run an attack first.');
            }
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('veltrix.stopAttack', () => {
            if (currentProcess) {
                currentProcess.kill('SIGINT');
                outputChannel.appendLine('\n[Stopping attack...]');
            } else {
                vscode.window.showInformationMessage('No attack is currently running.');
            }
        })
    );
}

export function deactivate() {
    if (currentProcess) {
        currentProcess.kill('SIGTERM');
    }
}
