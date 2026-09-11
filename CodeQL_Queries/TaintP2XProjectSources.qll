/** Generated from confirmed Source Identification results. */
import javascript

module TaintP2XProjectSources {
  predicate isConfirmedLLMFunction(Function function) {
    (
      function.getFile().getRelativePath() = "packages/components/src/followUpPrompts.ts" and
      function.getName() = "generateFollowUpPrompts" and
      function.getLocation().getStartLine() = 19 and
      function.getLocation().getEndLine() = 160
    )
    or
    (
      function.getFile().getRelativePath() = "packages/components/nodes/agents/AirtableAgent/AirtableAgent.ts" and
      function.getName() = "run" and
      function.getLocation().getStartLine() = 93 and
      function.getLocation().getEndLine() = 213
    )
    or
    (
      function.getFile().getRelativePath() = "packages/components/nodes/agents/AutoGPT/AutoGPT.ts" and
      function.getName() = "anonymous" and
      function.getLocation().getStartLine() = 214 and
      function.getLocation().getEndLine() = 222
    )
    or
    (
      function.getFile().getRelativePath() = "packages/components/nodes/agents/CSVAgent/CSVAgent.ts" and
      function.getName() = "run" and
      function.getLocation().getStartLine() = 80 and
      function.getLocation().getEndLine() = 222
    )
    or
    (
      function.getFile().getRelativePath() = "packages/components/nodes/agents/OpenAIAssistant/OpenAIAssistant.ts" and
      function.getName() = "run" and
      function.getLocation().getStartLine() = 181 and
      function.getLocation().getEndLine() = 847
    )
    or
    (
      function.getFile().getRelativePath() = "packages/components/nodes/agents/OpenAIAssistant/OpenAIAssistant.ts" and
      function.getName() = "openai.beta.threads.runs.retrieve" and
      function.getLocation().getStartLine() = 604 and
      function.getLocation().getEndLine() = 717
    )
    or
    (
      function.getFile().getRelativePath() = "packages/components/nodes/retrievers/RRFRetriever/ReciprocalRankFusion.ts" and
      function.getName() = "compressDocuments" and
      function.getLocation().getStartLine() = 23 and
      function.getLocation().getEndLine() = 62
    )
  }

  predicate isConfirmedLLMCall(DataFlow::CallNode call) {
    exists(Function function |
      isConfirmedLLMFunction(function) and
      call.getACallee() = function
    )
  }
}
