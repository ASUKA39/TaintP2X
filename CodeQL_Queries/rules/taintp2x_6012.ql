/**
 * Generated from Taint_Propagation/taint/taint.config.
 * @name User controlled string formatting
 * @kind problem
 * @problem.severity warning
 * @id taintp2x/6012
 * @tags security
 */
import javascript
import TaintP2XModels
import TaintP2XFlow

from DataFlow::Node source, DataFlow::Node sink
where
  TaintP2XFlow::flow(source, sink) and
  source instanceof TaintP2XModels::FromUrlLLMControlledSource and
  (sink instanceof TaintP2XModels::FormatStringSink)
select sink, "User controlled string is being formatted which may leak globally accessible data"
