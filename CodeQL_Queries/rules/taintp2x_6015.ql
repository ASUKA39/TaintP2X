/**
 * Generated from Taint_Propagation/taint/taint.config.
 * @name User controlled url
 * @kind problem
 * @problem.severity warning
 * @id taintp2x/6015
 * @tags security
 */
import javascript
import TaintP2XModels
import TaintP2XFlow

from DataFlow::Node source, DataFlow::Node sink
where
  TaintP2XFlow::flow(source, sink) and
  source instanceof TaintP2XModels::FromUrlLLMControlledSource and
  (sink instanceof TaintP2XModels::SSRFSink)
select sink, "User controlled data is used to get url"
