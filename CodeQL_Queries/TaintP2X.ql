/**
 * TaintP2X TypeScript dataflow query.
 *
 * @kind path-problem
 * @problem.severity warning
 * @id taintp2x/dataflow
 * @tags security
 */
import javascript
import TaintP2XModels
import TaintP2XFlow

from TaintP2XFlow::PathNode source, TaintP2XFlow::PathNode sink
where TaintP2XFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "TaintP2X data from " +
    source.getNode().(TaintP2XModels::TaintP2XSource).getKind() +
    " reaches " +
    sink.getNode().(TaintP2XModels::TaintP2XSink).getCategory()
