/**
 * TypeScript/JavaScript models corresponding to the original Pysa source and
 * sink categories. Models use CodeQL concepts or package-qualified API graphs;
 * unqualified method-name matching is intentionally excluded.
 */
import javascript
import TaintP2XProjectSources
import semmle.javascript.Concepts
import semmle.javascript.frameworks.ClientRequests
import semmle.javascript.frameworks.HTTP
import semmle.javascript.frameworks.Logging
import semmle.javascript.frameworks.SQL
import semmle.javascript.security.dataflow.CodeInjectionCustomizations
import semmle.javascript.security.dataflow.RequestForgeryCustomizations

module TaintP2XModels {
  newtype TFlowState = TNormal() or TFileOperation()

  class FlowState extends TFlowState {
    string toString() {
      this = TNormal() and result = "normal"
      or
      this = TFileOperation() and result = "FileOperation"
    }
  }

  module FlowState {
    FlowState normal() { result = TNormal() }

    FlowState fileOperation() { result = TFileOperation() }
  }

  abstract class TaintP2XSource extends DataFlow::Node {
    abstract string getKind();
  }

  abstract class TaintP2XSink extends DataFlow::Node {
    abstract string getCategory();

    predicate requiresFileOperation() { none() }

    FlowState getRequiredState() {
      result = FlowState::normal() and not this.requiresFileOperation()
      or
      result = FlowState::fileOperation() and this.requiresFileOperation()
    }
  }

  class LLMControlledSource extends TaintP2XSource {
    LLMControlledSource() {
      exists(DataFlow::FunctionNode function |
        TaintP2XProjectSources::isConfirmedLLMFunction(function.getFunction()) and
        this = function.getAReturn()
      )
    }

    override string getKind() { result = "LLMControlled" }
  }

  class FromUrlLLMControlledSource extends TaintP2XSource {
    FromUrlLLMControlledSource() {
      exists(StringLiteral literal |
        literal.getValue().regexpMatch("^https://[^/]*/chat.*") and
        this = DataFlow::valueNode(literal)
      )
      or
      exists(TemplateLiteral template, TemplateElement element |
        template.getNumElement() = 1 and
        element = template.getElement(0) and
        element.getValue().regexpMatch("^https://[^/]*/chat.*") and
        this = DataFlow::valueNode(template)
      )
    }

    override string getKind() { result = "FromUrlLLMControlled" }
  }

  class RemoteCodeExecutionSink extends TaintP2XSink {
    RemoteCodeExecutionSink() {
      this = any(CodeInjection::EvalJavaScriptSink sink)
      or
      this = any(CodeInjection::NodeJSVmSink sink)
      or
      exists(SystemCommandExecution execution |
        this = execution.getACommandArgument() and
        execution.isShellInterpreted(this)
      )
    }

    override string getCategory() { result = "RemoteCodeExecution" }
  }

  class ExecImportSink extends TaintP2XSink {
    ExecImportSink() {
      exists(DynamicImportExpr dynamicImport |
        this = DataFlow::valueNode(dynamicImport.getSource())
      )
      or
      exists(DataFlow::CallNode require |
        require = DataFlow::globalVarRef("require").getACall() and
        this = require.getArgument(0)
      )
    }

    override string getCategory() { result = "ExecImportSink" }
  }

  class ExecDeserializationSink extends TaintP2XSink {
    ExecDeserializationSink() {
      this =
        API::moduleImport("node-serialize")
            .getMember("unserialize")
            .getACall()
            .getArgument(0)
    }

    override string getCategory() { result = "ExecDeserializationSink" }
  }

  // Node deserializers consume data rather than an open file object, so the
  // Python FileContentDeserializationSink has no reliable direct equivalent.
  class FileContentDeserializationSink extends TaintP2XSink {
    FileContentDeserializationSink() { none() }

    override string getCategory() { result = "FileContentDeserializationSink" }
  }

  class ExecArgSink extends TaintP2XSink {
    ExecArgSink() {
      exists(SystemCommandExecution execution |
        this = execution.getACommandArgument() and
        not execution.isShellInterpreted(this)
        or
        this = execution.getArgumentList()
        or
        exists(DataFlow::PropRead read |
          read.getPropertyName() = "cwd" and
          read.getBase() = execution.getOptionsArg() and
          this = read
        )
      )
    }

    override string getCategory() { result = "ExecArgSink" }
  }

  class ExecEnvSink extends TaintP2XSink {
    ExecEnvSink() {
      exists(SystemCommandExecution execution |
        exists(DataFlow::PropRead read |
          read.getPropertyName() = "env" and
          read.getBase() = execution.getOptionsArg() and
          this = read
        )
      )
    }

    override string getCategory() { result = "ExecEnvSink" }
  }

  class FileSystem_OtherSink extends TaintP2XSink {
    FileSystem_OtherSink() {
      exists(FileSystemAccess access |
        not access instanceof FileSystemReadAccess and
        not access instanceof FileSystemWriteAccess and
        this = access.getAPathArgument()
      )
    }

    override string getCategory() { result = "FileSystem_Other" }
  }

  class FileSystem_ReadWriteSink extends TaintP2XSink {
    FileSystem_ReadWriteSink() {
      this = any(FileSystemReadAccess read).getAPathArgument()
      or
      this = any(FileSystemWriteAccess write).getAPathArgument()
    }

    override string getCategory() { result = "FileSystem_ReadWrite" }
  }

  class EmailSendSink extends TaintP2XSink {
    EmailSendSink() {
      this =
        API::moduleImport("nodemailer")
            .getMember("createTransport")
            .getACall()
            .getReturn()
            .getMember("sendMail")
            .getACall()
            .getArgument(0)
      or
      this = API::moduleImport("@sendgrid/mail").getMember("send").getACall().getArgument(0)
    }

    override string getCategory() { result = "EmailSend" }
  }

  class SQLSink extends TaintP2XSink {
    SQLSink() { this = any(SQL::SqlString sql) }

    override string getCategory() { result = "SQL" }
  }

  class XSSSink extends TaintP2XSink {
    XSSSink() { this = any(Http::ResponseSendArgument response) }

    override string getCategory() { result = "XSS" }
  }

  // JavaScript has no direct semantic equivalent of Python str.format.
  class FormatStringSink extends TaintP2XSink {
    FormatStringSink() { none() }

    override string getCategory() { result = "FormatString" }
  }

  class ReturnedToUserSink extends TaintP2XSink {
    ReturnedToUserSink() { this = any(Http::ResponseSendArgument response) }

    override string getCategory() { result = "ReturnedToUser" }

    override predicate requiresFileOperation() { any() }
  }

  class ResponseHeaderValueSink extends TaintP2XSink {
    ResponseHeaderValueSink() {
      exists(Http::ExplicitHeaderDefinition header |
        header.definesHeaderValue(_, this)
      )
    }

    override string getCategory() { result = "ResponseHeaderValue" }
  }

  class ResponseHeaderNameSink extends TaintP2XSink {
    ResponseHeaderNameSink() {
      this = any(Http::ExplicitHeaderDefinition header).getNameNode()
    }

    override string getCategory() { result = "ResponseHeaderName" }
  }

  class LoggingSink extends TaintP2XSink {
    LoggingSink() { this = any(LoggerCall call).getAMessageComponent() }

    override string getCategory() { result = "Logging" }
  }

  class SSRFSink extends TaintP2XSink {
    SSRFSink() { this = any(RequestForgery::Sink sink) }

    override string getCategory() { result = "SSRFSink" }
  }

  predicate isFileOperationStep(DataFlow::Node input, DataFlow::Node output) {
    exists(FileSystemReadAccess read |
      input = read.getAPathArgument() and
      output = read.getADataNode()
    )
  }
}
