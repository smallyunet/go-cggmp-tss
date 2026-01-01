const fs = require('fs');
require('./wasm_exec.js');

const go = new Go();
const wasmBuffer = fs.readFileSync('./main.wasm');

WebAssembly.instantiate(wasmBuffer, go.importObject).then((result) => {
    // Run the WASM binary
    // This blocks if the Go program blocks only (it triggers main), 
    // but our main waits on a channel, so it shouldn't return?
    // Wait, if it waits on a channel, `go.run` will not return until exit.
    // The Go `main` function I wrote: `<-c`.
    // So `go.run` will block.
    // In Node.js, this might be an issue.
    // Usually we run it without waiting? 
    // Or we rely on the fact that `go.run` is async? No, it's usually sync or promise based?
    // `go.run(instance)` returns a Promise that resolves when the program exits.
    // So we should NOT await it if we want to interact with it, unless it exits immediately.
    // But if it exits, the callbacks might go away?

    go.run(result.instance);

    // In Node.js, we can start testing now. (Assuming go.run starts incorrectly blocking or we need to be careful).
    // Actually, `go.run` runs the Go program. If the Go program blocks (e.g. select{}), `go.run` returns a pending promise.
    // We can proceed.

    console.log("WASM loaded. GoCGGMP:", global.GoCGGMP);

    startTest();
}).catch(err => {
    console.error("Failed to instantiate WASM:", err);
    process.exit(1);
});

async function startTest() {
    console.log("Starting 3-Party KeyGen Test (Node.js)...");

    const GoCGGMP = global.GoCGGMP;
    if (!GoCGGMP) {
        console.error("GoCGGMP global not found!");
        process.exit(1);
    }

    const parties = ["1", "2", "3"];
    const threshold = 1;
    const sessions = {};

    // 1. Initialize
    for (const pid of parties) {
        const params = {
            partyID: pid,
            allParties: parties,
            threshold: threshold,
            sessionID: "sess-node-1",
            oneRoundKeyGen: true
        };

        try {
            const respStr = GoCGGMP.NewKeyGen(JSON.stringify(params));
            const resp = JSON.parse(respStr);
            sessions[pid] = {
                id: resp.sessionID,
                msgs: resp.messages || []
            };
            console.log(`[${pid}] Initialized. Msgs: ${sessions[pid].msgs.length}`);
        } catch (e) {
            console.error(`[${pid}] Init Error:`, e);
            process.exit(1);
        }
    }

    // 2. Initial Message Routing
    let allMsgs = [];
    for (const pid of parties) {
        sessions[pid].msgs.forEach(m => allMsgs.push(m));
        sessions[pid].msgs = [];
    }

    console.log(`Routing ${allMsgs.length} messages...`);

    // 3. Process Updates
    for (const pid of parties) {
        const s = sessions[pid];
        for (const msg of allMsgs) {
            if (msg.from === pid) continue;
            if (!msg.isBroadcast && !msg.to.includes(pid)) continue;

            console.log(`[${pid}] Processing ${msg.isBroadcast ? "Bcast" : "P2P"} from ${msg.from} type=${msg.type} to=${JSON.stringify(msg.to)}`);

            const msgJson = JSON.stringify(msg);
            try {
                // console.log(`[${pid}] Updating...`);
                const outStr = GoCGGMP.Update(s.id, msgJson);
                // Check if result starts with "error:"
                if (outStr.startsWith("error:")) {
                    throw new Error(outStr);
                }
                const out = JSON.parse(outStr);
                // Should be empty for 1-Round finish
            } catch (e) {
                console.error(`[${pid}] Update Error:`, e);
                process.exit(1);
            }
        }
    }

    // 4. Check Results
    let pubKeyX = "";
    for (const pid of parties) {
        try {
            const resStr = GoCGGMP.Result(sessions[pid].id);
            if (!resStr) {
                console.error(`[${pid}] Failed to get result (not finished)`);
                process.exit(1);
            }
            const res = JSON.parse(resStr);
            console.log(`[${pid}] Finished. PubKeyX: ${res.PublicKeyX}`);

            if (pubKeyX === "") {
                pubKeyX = res.PublicKeyX;
            } else if (pubKeyX !== res.PublicKeyX) {
                console.error("Public Key Mismatch!");
                process.exit(1);
            }

        } catch (e) {
            console.error(`[${pid}] Result Error:`, e);
            process.exit(1);
        }
    }

    console.log("SUCCESS: All parties finished with matching keys.");
    process.exit(0);
}
