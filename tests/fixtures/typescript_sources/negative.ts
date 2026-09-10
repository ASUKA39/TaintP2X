import OpenAI from "openai"

const database = {
  create() {
    return "ordinary"
  }
}

const modelCache = {
  run() {
    return "ordinary"
  }
}

export function ordinaryCalls() {
  void OpenAI
  return `${database.create()}:${modelCache.run()}`
}
