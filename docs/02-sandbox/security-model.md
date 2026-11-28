# SafeRun Sandbox Security Model

SafeRun stages the project and runs npm against a verified lockfile in a disposable Docker container. The staged project is the writable workspace. The host project and its existing dependencies remain outside that mount.

## Current controls

- Docker drops all capabilities and sets `no-new-privileges`.
- CPU, memory, and process limits constrain resource use. The container root filesystem is read-only, with a restricted writable temporary filesystem and a writable staged workspace.
- SafeRun compares workspace snapshots and samples process and TCP activity during the install. Short-lived activity can fall between samples.
- The default Docker bridge network permits outbound traffic. `network.allowed_hosts` affects how SafeRun classifies observed connections. Egress controls require network-layer enforcement.
- Containers and temporary workspaces are removed after the scan.

## Host installation

After policy evaluation and approval, SafeRun installs with lifecycle scripts disabled using the reviewed lockfile. It verifies the staged host dependency tree before publishing it and restores npm metadata and dependencies if publishing or rebuilding fails.

`--allow-host-scripts` requests a separate confirmation for `npm rebuild`. Opted-in scripts run outside Docker with the user's access. Rollback covers npm metadata and `node_modules`. Other filesystem effects and remote actions are outside that scope.
