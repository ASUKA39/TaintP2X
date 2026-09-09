/**
 * TaintP2X TypeScript proof-of-concept for CWE-94.
 *
 * The query keeps the CodeQL JavaScript extractor and official data-flow
 * library as the analysis backend. The project-specific LLM source model is
 * represented by LLMControlledSource below and can be extended as more SDKs
 * are confirmed by Source Identification.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision medium
 * @id taintp2x/typescript-cwe-094
 * @tags security external/cwe/cwe-094
 */
import javascript

class DynamicFunctionSink extends DataFlow::Node {
  DynamicFunctionSink() {
    this = DataFlow::globalVarRef("Function").getAnInvocation().getAnArgument()
  }
}

class LLMControlledSource extends DataFlow::Node {
  LLMControlledSource() {
    exists(DataFlow::PropRead read |
      read.getPropertyName() in ["content", "text", "response", "output", "customToolSchema"] and
      this = read
    )
    or
    exists(DataFlow::CallNode call |
      call = DataFlow::globalVarRef(["fetch", "axios", "request"]).getAnInvocation() and
      this = call
    )
    or
    exists(DataFlow::CallNode call |
      call.getCalleeName() in ["invoke", "generate", "complete", "createChatCompletion", "call"] and
      this = call
    )
  }
}

module FlowConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof LLMControlledSource }
  predicate isSink(DataFlow::Node sink) { sink instanceof DynamicFunctionSink }
}

module Flow = TaintTracking::Global<FlowConfig>;
import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "LLM-controlled data reaches a dynamic Function constructor"
