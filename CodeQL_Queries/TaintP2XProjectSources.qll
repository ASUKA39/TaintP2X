/** Generated from confirmed Source Identification results. */
import javascript

module TaintP2XProjectSources {
  predicate isConfirmedLLMFunction(Function function) {
    (
      function.getFile().getRelativePath() = "packages/components/nodes/agents/AirtableAgent/AirtableAgent.ts" and
      function.getName() = "run" and
      function.getLocation().getStartLine() = 93 and
      function.getLocation().getEndLine() = 213
    )
    or
    (
      function.getFile().getRelativePath() = "packages/components/nodes/agents/AutoGPT/AutoGPT.ts" and
      function.getName() = "executor.chain.call" and
      function.getLocation().getStartLine() = 125 and
      function.getLocation().getEndLine() = 182
    )
    or
    (
      function.getFile().getRelativePath() = "packages/components/nodes/agents/AutoGPT/AutoGPT.ts" and
      function.getName() = "LLMChain.call" and
      function.getLocation().getStartLine() = 214 and
      function.getLocation().getEndLine() = 222
    )
  }

  predicate isConfirmedLLMCall(DataFlow::CallNode call) {
    exists(Function function |
      isConfirmedLLMFunction(function) and
      call.getACallee() = function
    )
  }
}
