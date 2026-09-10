/**
 * Generated from Taint_Propagation/taint/taint.config.
 * @name XSS
 * @kind problem
 * @problem.severity warning
 * @id taintp2x/6009
 * @tags security
 */
import javascript
import TaintP2XModels
import TaintP2XFlow

from DataFlow::Node source, DataFlow::Node sink
where
  TaintP2XFlow::flow(source, sink) and
  source instanceof TaintP2XModels::FromUrlLLMControlledSource and
  (sink instanceof TaintP2XModels::XSSSink)
select sink, "Data from [{$sources}] source(s) may reach [{$sinks}] sink(s)"
