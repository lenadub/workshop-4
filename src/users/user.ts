import bodyParser from "body-parser";
import express, { Request, Response } from "express";
import { BASE_USER_PORT, REGISTRY_PORT, BASE_ONION_ROUTER_PORT } from "../config";
import { createRandomSymmetricKey, exportSymKey, rsaEncrypt, symEncrypt } from "../crypto";
import fetch from "node-fetch";

export type SendMessageBody = {
  message: string;
  destinationUserId: number;
};

export async function user(userId: number) {
  const _user = express();
  _user.use(express.json());
  _user.use(bodyParser.json());

  let lastReceivedMessage: string | null = null;
  let lastSentMessage: string | null = null;
  let lastCircuit: number[] = [];

  _user.get("/status", (req, res) => {
    res.send("live");
  });

  _user.get("/getLastReceivedMessage", (req: Request, res: Response) => {
    res.json({ result: lastReceivedMessage });
  });

  _user.get("/getLastSentMessage", (req: Request, res: Response) => {
    res.json({ result: lastSentMessage });
  });

  _user.get("/getLastCircuit", (req: Request, res: Response) => {
    res.json({ result: lastCircuit });
  });
  _user.post("/message", (req: Request, res: Response) => {
    try {
      const { message }: { message: string } = req.body;
      if (message === undefined || message === null) {
        return res.status(400).json({ message: "Message is required" });
      }
  
      // Function to check if a string is Base64-encoded
      function isBase64(str: string): boolean {
        try {
          return btoa(atob(str)) === str; // Decoding and re-encoding should return the same string
        } catch (err) {
          return false; // If an error occurs, it's not valid Base64
        }
      }
  
      // Decode message only if it's in Base64 format
      const decodedMessage = isBase64(message) ? Buffer.from(message, "base64").toString("utf-8") : message;
  
      // Store the final message
      lastReceivedMessage = decodedMessage;
  
      return res.status(200).send("success");
    } catch (error) {
      console.error("Error handling message:", error);
      return res.status(500).json({ error: "Internal server error" });
    }
  });
  
  

  _user.post("/sendMessage", async (req: Request, res: Response) => {
    const { message, destinationUserId }: { message: string; destinationUserId: number } = req.body;

    if (!message || typeof destinationUserId !== "number") {
        return res.status(400).json({ error: "Invalid message or destination user ID" });
    }

    try {
        const response = await fetch(`http://localhost:${REGISTRY_PORT}/getNodeRegistry`);
        if (!response.ok) {
            return res.status(500).json({ error: "Failed to fetch node registry" });
        }

        const nodeRegistry = (await response.json()) as { nodes: { nodeId: number; pubKey: string }[] };
        if (!nodeRegistry.nodes || nodeRegistry.nodes.length < 3) {
            return res.status(500).json({ error: "Not enough nodes in the network" });
        }

        // Fisher-Yates Shuffle for unbiased random node selection
        function shuffleArray(array: any[]) {
            for (let i = array.length - 1; i > 0; i--) {
                const j = Math.floor(Math.random() * (i + 1));
                [array[i], array[j]] = [array[j], array[i]]; // Swap elements
            }
            return array;
        }

        // Select a unique circuit of 3 random nodes using Fisher-Yates Shuffle
        const shuffledNodes = shuffleArray([...nodeRegistry.nodes]).slice(0, 3);
        const circuit = shuffledNodes.map(node => node.nodeId);

        lastCircuit = circuit; // Store the last used circuit

        let payload = btoa(message); // Encode message to Base64

        for (let i = 2; i >= 0; i--) {
            const nodeId = circuit[i];
            const nodeInfo = nodeRegistry.nodes.find((node) => node.nodeId === nodeId);
            if (!nodeInfo) {
                return res.status(500).json({ error: "Node information missing" });
            }

            // Generate a symmetric key
            const symKey = await createRandomSymmetricKey();
            const strSymKey = await exportSymKey(symKey);

            // Determine the next hop
            const destination = i === 2 ? BASE_USER_PORT + destinationUserId : BASE_ONION_ROUTER_PORT + circuit[i + 1];

            // Encrypt destination and message
            const paddedDestination = destination.toString().padStart(10, "0");
            const encryptedLayer = await symEncrypt(symKey, btoa(paddedDestination + payload)); // Encode payload
            const encryptedSymKey = await rsaEncrypt(btoa(strSymKey), nodeInfo.pubKey); // Encode symmetric key

            payload = encryptedSymKey + encryptedLayer;
            console.log(`[User ${userId}] Sending Encrypted Message: ${payload}`);
            console.log(`[User ${userId}] Expected Destination Prefix: ${destination.toString().padStart(10, "0")}`);

        }

        // Send message to the first node
        const firstNodeId = circuit[0];
        await fetch(`http://localhost:${BASE_ONION_ROUTER_PORT + firstNodeId}/message`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ message: payload }),
        });

        lastSentMessage = message;
        return res.status(200).json({ message: "Message sent successfully" });
    } catch (error) {
        return res.status(500).json({ error: "Error sending message", details: String(error) });
    }
});



  const server = _user.listen(BASE_USER_PORT + userId, () => {
    console.log(`User ${userId} is listening on port ${BASE_USER_PORT + userId}`);
  });

  return server;
}
