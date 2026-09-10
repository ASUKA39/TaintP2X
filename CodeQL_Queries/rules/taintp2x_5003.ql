/**
 * Generated from Taint_Propagation/taint/taint.config.
 * @name Possible ExecDeserializationSink:
 * @kind problem
 * @problem.severity warning
 * @id taintp2x/5003
 * @tags security
 */
import javascript
import TaintP2XModels
import TaintP2XFlow

from DataFlow::Node source, DataFlow::Node sink
where
  TaintP2XFlow::flow(source, sink) and
  source instanceof TaintP2XModels::LLMControlledSource and
  (sink instanceof TaintP2XModels::ExecDeserializationSink)
select sink, "User specified data may reach a code execution sink"
