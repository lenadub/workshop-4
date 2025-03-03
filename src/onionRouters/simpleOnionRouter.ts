import bodyParser from "body-parser";
import express, { Request, Response } from "express";
import { BASE_ONION_ROUTER_PORT, REGISTRY_PORT, BASE_USER_PORT } from "../config";
import { generateRsaKeyPair, exportPubKey, exportPrvKey, importPrvKey, rsaDecrypt, symDecrypt } from "../crypto";
import fetch from "node-fetch";

// Create a global storage system for the nodes and their state
declare global {
  var keyStore: Record<number, { publicKey: string; privateKey: string | null }>;
  var nodeStatus: Record<number, { 
    lastReceivedEncryptedMessage: string | null;
    lastReceivedDecryptedMessage: string | null;
    lastMessageDestination: number | null;
  }>;
}

export async function simpleOnionRouter(nodeId: number) {
  const app = express();
  app.use(express.json());
  app.use(bodyParser.json());

  // Initialize global key store and node status if not already done
  initializeGlobalStorage(nodeId);

  // Register the current node
  await registerNodeToRegistry(nodeId);

  // Helper function to initialize global storage
  function initializeGlobalStorage(nodeId: number) {
    if (!globalThis.keyStore) globalThis.keyStore = {};
    if (!globalThis.nodeStatus) globalThis.nodeStatus = {};

    if (!globalThis.keyStore[nodeId]) {
      generateAndStoreKeys(nodeId);
    }

    if (!globalThis.nodeStatus[nodeId]) {
      globalThis.nodeStatus[nodeId] = {
        lastReceivedEncryptedMessage: null,
        lastReceivedDecryptedMessage: null,
        lastMessageDestination: null,
      };
    }
  }

  // Generate RSA keys and store them globally
  async function generateAndStoreKeys(nodeId: number) {
    const { publicKey, privateKey } = await generateRsaKeyPair();
    const publicKeyBase64 = await exportPubKey(publicKey);
    const privateKeyBase64 = await exportPrvKey(privateKey);

    globalThis.keyStore[nodeId] = { publicKey: publicKeyBase64, privateKey: privateKeyBase64 };
  }

  // Function to register the node by sending its public key to the registry
  async function registerNodeToRegistry(nodeId: number) {
    try {
      const { publicKey } = globalThis.keyStore[nodeId];

      const response = await fetch(`http://localhost:${REGISTRY_PORT}/registerNode`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ nodeId, pubKey: publicKey }),
      });

      if (!response.ok) {
        throw new Error("Node registration failed");
      }

      console.log(`Node ${nodeId} successfully registered.`);
    } catch (error) {
      console.error("Error during node registration:", error);
    }
  }

  // Implement the /status route
  app.get("/status", (req, res) => {
    res.send("live");
  });

  // Implement the /getPrivateKey route to return the private key of the node
  app.get("/getPrivateKey", (req: Request, res: Response) => {
    const nodePort = req.socket.localPort;
    
    // Ensure nodePort is defined
    if (!nodePort) {
      return res.status(400).json({ message: "Node port is undefined" });
    }
  
    const extractedNodeId = nodePort - BASE_ONION_ROUTER_PORT;
  
    // Retrieve the private key from the globally stored node keys
    const node = globalThis.keyStore[extractedNodeId];
    if (!node) {
      return res.status(404).json({ message: "Node not found" });
    }
  
    // Return the private key in base64 format
    return res.json({ result: node.privateKey });
  });

  // Implement the /getLastReceivedEncryptedMessage route
  app.get("/getLastReceivedEncryptedMessage", (req: Request, res: Response) => {
    res.json({ result: globalThis.nodeStatus[nodeId].lastReceivedEncryptedMessage });
  });

  // Implement the /getLastReceivedDecryptedMessage route
  app.get("/getLastReceivedDecryptedMessage", (req: Request, res: Response) => {
    res.json({ result: globalThis.nodeStatus[nodeId].lastReceivedDecryptedMessage });
  });

  // Implement the /getLastMessageDestination route
  app.get("/getLastMessageDestination", (req: Request, res: Response) => {
    res.json({ result: globalThis.nodeStatus[nodeId].lastMessageDestination });
  });

  // Implement the /message route to handle encrypted messages and forward them
  app.post("/message", async (req: Request, res: Response) => {
    const { message }: { message: string } = req.body;
    if (!message) {
        return res.status(400).json({ error: "Message is required" });
    }
    console.log(`[Node ${nodeId}] Received Encrypted Message: ${message}`);


    try {
        globalThis.nodeStatus[nodeId].lastReceivedEncryptedMessage = message;

        // Retrieve private key
        const privateKeyBase64 = globalThis.keyStore[nodeId]?.privateKey;
        if (!privateKeyBase64) {
            return res.status(500).json({ error: "Private key missing" });
        }

        const privateKey = await importPrvKey(privateKeyBase64);

        // Decrypt the RSA layer (decrypting the encrypted symmetric key)
        const decryptedSymKeyBase64 = await rsaDecrypt(message.slice(0, 344), privateKey);
        const decryptedSymKey = atob(decryptedSymKeyBase64); // Convert Base64 to string

        // Decrypt the symmetric layer
        const decryptedMessageBase64 = await symDecrypt(decryptedSymKey, message.slice(344));
        const decryptedMessage = Buffer.from(decryptedMessageBase64, "base64").toString("utf-8");


        globalThis.nodeStatus[nodeId].lastReceivedDecryptedMessage = decryptedMessage;

        // Extract destination
        const destinationStr = decryptedMessage.slice(0, 10);
        const nextPayload = decryptedMessage.slice(10).trim(); // Trim extra spaces
        
        if (!/^\d+$/.test(destinationStr)) {
            console.error(`[Node ${nodeId}] ERROR: Extracted destination "${destinationStr}" is not a valid number!`);
            return res.status(500).json({ error: "Invalid destination format" });
        }
        
        const destination = parseInt(destinationStr, 10);
        

        globalThis.nodeStatus[nodeId].lastMessageDestination = destination;

        console.log(`[Node ${nodeId}] Forwarding message to: ${destination}`);
        console.log(`[Node ${nodeId}] Decrypted message: "${nextPayload.length === 0 ? "<EMPTY MESSAGE>" : nextPayload}"`);

        // If destination is a user, send the final message
        if (destination >= BASE_USER_PORT) {
            console.log(`[Node ${nodeId}] Final destination reached. Forwarding to User ${destination - BASE_USER_PORT}.`);
            await fetch(`http://localhost:${destination}/message`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ message: nextPayload }),
            });
            return res.status(200).json({ message: "Final message delivered to user" });
        }

        // Otherwise, forward to the next node
        await fetch(`http://localhost:${destination}/message`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ message: nextPayload }),
        });

        return res.status(200).json({ message: "Message forwarded successfully" });
    } catch (error) {
        console.error(`[Node ${nodeId}] Error while decrypting message:`, error);
        return res.status(500).json({ error: "Error processing message", details: String(error) });
    }
});





  // Start the server for the onion router
  const server = app.listen(BASE_ONION_ROUTER_PORT + nodeId, () => {
    console.log(`Router ${nodeId} is running on port ${BASE_ONION_ROUTER_PORT + nodeId}`);
  });

  return server;
}
