declare module "openai" {
  export default class OpenAI {
    chat: {
      completions: {
        create(input: object): Promise<unknown>
      }
    }
  }
}

declare module "ai" {
  export function generateText(input: object): Promise<unknown>
}

declare module "@google/generative-ai" {
  export class GenerativeModel {
    generateContent(input: string): Promise<unknown>
  }

  export class GoogleGenerativeAI {
    getGenerativeModel(input: object): GenerativeModel
  }
}
