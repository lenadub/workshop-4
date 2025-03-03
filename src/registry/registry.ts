import bodyParser from "body-parser";
import express, { Request, Response } from "express";
import { REGISTRY_PORT } from "../config";

// Node type definition
export type Node = { nodeId: number; pubKey: string};

export type GetNodeRegistryBody = {
  nodes: Node[];
};
// Define registry response type
export type RegistryResponse = { nodes: Node[] };

// In-memory storage for registered nodes
let nodes: Node[] = []; // Initialize nodes array

// Function to register a new node (without key generation)
async function registerNode(nodeId: number, pubKey: string) {
  // Only store the node, no key generation here
  const newNode: Node = { nodeId, pubKey};
  nodes.push(newNode);
  return newNode;
}

export async function launchRegistry() {
  const _registry = express();
  _registry.use(express.json());
  _registry.use(bodyParser.json());

  // Implement the /status route
  _registry.get("/status", (req, res) => {
    res.send("live");
  });

  // Implement the /registerNode route to register a node
  // @ts-ignore
  _registry.post("/registerNode", async (req: Request, res: Response) => {
    const { nodeId, pubKey }: { nodeId: number; pubKey: string } = req.body;
    if (nodeId === undefined || typeof nodeId !== "number" || !pubKey) {
      res.status(400).json({ error: "Missing nodeId or public key" });
      return;
    }
    if (nodes.some(node => node.nodeId === nodeId)) {
      res.status(400).json({ error: "Node is already registered" });
      return;
    }

    try {
      // Register the node by storing it (without generating keys)
      const registeredNode = await registerNode(nodeId, pubKey);
      res.status(201).json({ message: "Node registered successfully", node: registeredNode });
    } catch (error) {
      res.status(500).json({ message: "Error registering node", error });
    }
  });

  // Endpoint to get the list of all registered nodes
  _registry.get("/getNodeRegistry", (req: Request, res: Response) => {
    const registryResponse: RegistryResponse = { nodes };
    return res.json(registryResponse);  // Return nodes array
  });

  // Start the server and listen on the port defined by REGISTRY_PORT
  const server = _registry.listen(REGISTRY_PORT, () => {
    console.log(`Registry is listening on port ${REGISTRY_PORT}`);
  });

  return server;
}
