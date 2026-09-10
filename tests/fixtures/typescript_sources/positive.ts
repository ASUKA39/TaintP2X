import OpenAIClient from "openai"
import { generateText as generate } from "ai"
import { GoogleGenerativeAI } from "@google/generative-ai"
import { AIClient } from "./wrapper"

const moduleClient = new OpenAIClient()

export async function moduleVariable(prompt: string) {
  return moduleClient.chat.completions.create({ messages: [{ role: "user", content: prompt }] })
}

export async function directApi(prompt: string) {
  return generate({ prompt })
}

export async function reexportedClient(prompt: string) {
  const client = new AIClient()
  return client.chat.completions.create({ messages: [{ role: "user", content: prompt }] })
}

export async function factoryClient(prompt: string) {
  const google = new GoogleGenerativeAI()
  const model = google.getGenerativeModel({ model: "gemini" })
  return model.generateContent(prompt)
}

class FieldAgent {
  private client = new OpenAIClient()

  async answer(prompt: string) {
    const alias = this.client
    const { chat } = alias
    await chat.completions.create({ messages: [{ role: "user", content: prompt }] })
    return alias?.chat.completions.create({ messages: [{ role: "user", content: prompt }] })
  }
}

class ParameterAgent {
  constructor(private readonly client: OpenAIClient) {}

  async answer(prompt: string) {
    return this.client.chat.completions.create({ messages: [{ role: "user", content: prompt }] })
  }
}
