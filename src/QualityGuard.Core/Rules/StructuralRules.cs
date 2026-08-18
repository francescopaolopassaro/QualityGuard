using QualityGuard.Core.Analysis;
using QualityGuard.Core.Models;
using QualityGuard.Core.Semantics;
using QualityGuard.Core.Syntax;
using QualityGuard.Core.Tokenization;

namespace QualityGuard.Core.Rules;

/// <summary>
/// Rules that need the syntax tree: they reason about statements, branches and functions rather than
/// about lines or single tokens, and therefore apply to every language the parser understands.
/// </summary>
public static class StructuralRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new UnreachableCodeAfterJumpRuleCs(),
        new UnreachableCodeAfterJumpRuleJava(),
        new UnreachableCodeAfterJumpRuleKotlin(),
        new UnreachableCodeAfterJumpRuleJs(),
        new UnreachableCodeAfterJumpRulePython(),
        new UnreachableCodeAfterJumpRulePhp(),
        new UnreachableCodeAfterJumpRuleGo(),
        new UnreachableCodeAfterJumpRuleDart(),
        new UnreachableCodeAfterJumpRuleRuby(),
        new UnreachableCodeAfterJumpRuleSwift(),
        new UnreachableCodeAfterJumpRuleCss(),
        new UnreachableCodeAfterJumpRuleHtml(),
        new UnreachableCodeAfterJumpRuleXml(),
        new UnreachableCodeAfterJumpRuleTerraform(),
        new UnreachableCodeAfterJumpRuleDockerfile(),
        new UnreachableCodeAfterJumpRuleKubernetes(),
        new UnreachableCodeAfterJumpRuleCloudFormation(),
        new UnreachableCodeAfterJumpRuleJson(),
        new DuplicateConditionRuleCs(),
        new DuplicateConditionRuleJava(),
        new DuplicateConditionRuleKotlin(),
        new DuplicateConditionRuleJs(),
        new DuplicateConditionRulePython(),
        new DuplicateConditionRulePhp(),
        new DuplicateConditionRuleGo(),
        new DuplicateConditionRuleDart(),
        new DuplicateConditionRuleRuby(),
        new DuplicateConditionRuleSwift(),
        new DuplicateConditionRuleCss(),
        new DuplicateConditionRuleHtml(),
        new DuplicateConditionRuleXml(),
        new DuplicateConditionRuleTerraform(),
        new DuplicateConditionRuleDockerfile(),
        new DuplicateConditionRuleKubernetes(),
        new DuplicateConditionRuleCloudFormation(),
        new DuplicateConditionRuleJson(),
        new ConstantConditionRuleCs(),
        new ConstantConditionRuleJava(),
        new ConstantConditionRuleKotlin(),
        new ConstantConditionRuleJs(),
        new ConstantConditionRulePython(),
        new ConstantConditionRulePhp(),
        new ConstantConditionRuleGo(),
        new ConstantConditionRuleDart(),
        new ConstantConditionRuleRuby(),
        new ConstantConditionRuleSwift(),
        new ConstantConditionRuleCss(),
        new ConstantConditionRuleHtml(),
        new ConstantConditionRuleXml(),
        new ConstantConditionRuleTerraform(),
        new ConstantConditionRuleDockerfile(),
        new ConstantConditionRuleKubernetes(),
        new ConstantConditionRuleCloudFormation(),
        new ConstantConditionRuleJson(),
        new SelfAssignmentRuleCs(),
        new SelfAssignmentRuleJava(),
        new SelfAssignmentRuleKotlin(),
        new SelfAssignmentRuleJs(),
        new SelfAssignmentRulePython(),
        new SelfAssignmentRulePhp(),
        new SelfAssignmentRuleGo(),
        new SelfAssignmentRuleDart(),
        new SelfAssignmentRuleRuby(),
        new SelfAssignmentRuleSwift(),
        new SelfAssignmentRuleCss(),
        new SelfAssignmentRuleHtml(),
        new SelfAssignmentRuleXml(),
        new SelfAssignmentRuleTerraform(),
        new SelfAssignmentRuleDockerfile(),
        new SelfAssignmentRuleKubernetes(),
        new SelfAssignmentRuleCloudFormation(),
        new SelfAssignmentRuleJson(),
        new IdenticalOperandsRuleCs(),
        new IdenticalOperandsRuleJava(),
        new IdenticalOperandsRuleKotlin(),
        new IdenticalOperandsRuleJs(),
        new IdenticalOperandsRulePython(),
        new IdenticalOperandsRulePhp(),
        new IdenticalOperandsRuleGo(),
        new IdenticalOperandsRuleDart(),
        new IdenticalOperandsRuleRuby(),
        new IdenticalOperandsRuleSwift(),
        new IdenticalOperandsRuleCss(),
        new IdenticalOperandsRuleHtml(),
        new IdenticalOperandsRuleXml(),
        new IdenticalOperandsRuleTerraform(),
        new IdenticalOperandsRuleDockerfile(),
        new IdenticalOperandsRuleKubernetes(),
        new IdenticalOperandsRuleCloudFormation(),
        new IdenticalOperandsRuleJson(),
        new IdenticalBranchesRuleCs(),
        new IdenticalBranchesRuleJava(),
        new IdenticalBranchesRuleKotlin(),
        new IdenticalBranchesRuleJs(),
        new IdenticalBranchesRulePython(),
        new IdenticalBranchesRulePhp(),
        new IdenticalBranchesRuleGo(),
        new IdenticalBranchesRuleDart(),
        new IdenticalBranchesRuleRuby(),
        new IdenticalBranchesRuleSwift(),
        new IdenticalBranchesRuleCss(),
        new IdenticalBranchesRuleHtml(),
        new IdenticalBranchesRuleXml(),
        new IdenticalBranchesRuleTerraform(),
        new IdenticalBranchesRuleDockerfile(),
        new IdenticalBranchesRuleKubernetes(),
        new IdenticalBranchesRuleCloudFormation(),
        new IdenticalBranchesRuleJson(),
        new TooManyParametersRuleCs(),
        new TooManyParametersRuleJava(),
        new TooManyParametersRuleKotlin(),
        new TooManyParametersRuleJs(),
        new TooManyParametersRulePython(),
        new TooManyParametersRulePhp(),
        new TooManyParametersRuleGo(),
        new TooManyParametersRuleDart(),
        new TooManyParametersRuleRuby(),
        new TooManyParametersRuleSwift(),
        new TooManyParametersRuleCss(),
        new TooManyParametersRuleHtml(),
        new TooManyParametersRuleXml(),
        new TooManyParametersRuleTerraform(),
        new TooManyParametersRuleDockerfile(),
        new TooManyParametersRuleKubernetes(),
        new TooManyParametersRuleCloudFormation(),
        new TooManyParametersRuleJson(),
        new FunctionTooLongRuleJava(),
        new FunctionTooLongRuleJs(),
        new FunctionTooLongRuleDart(),
        new FunctionTooLongRuleRuby(),
        new FunctionTooLongRuleSwift(),
        new FunctionTooLongRuleCss(),
        new FunctionTooLongRuleHtml(),
        new FunctionTooLongRuleXml(),
        new FunctionTooLongRuleTerraform(),
        new FunctionTooLongRuleDockerfile(),
        new FunctionTooLongRuleKubernetes(),
        new FunctionTooLongRuleCloudFormation(),
        new FunctionTooLongRuleJson(),
        new CognitiveComplexityRuleCs(),
        new CognitiveComplexityRuleJava(),
        new CognitiveComplexityRuleJs(),
        new CognitiveComplexityRulePython(),
        new CognitiveComplexityRulePhp(),
        new CognitiveComplexityRuleGo(),
        new CognitiveComplexityRuleRuby(),
        new CognitiveComplexityRuleSwift(),
        new CognitiveComplexityRuleCss(),
        new CognitiveComplexityRuleHtml(),
        new CognitiveComplexityRuleXml(),
        new CognitiveComplexityRuleTerraform(),
        new CognitiveComplexityRuleDockerfile(),
        new CognitiveComplexityRuleKubernetes(),
        new CognitiveComplexityRuleCloudFormation(),
        new CognitiveComplexityRuleJson(),
        new CognitiveComplexityRuleKotlin(),
        new CognitiveComplexityRuleDart(),
        new DeepNestingRuleJava(),
        new DeepNestingRuleJs(),
        new DeepNestingRulePython(),
        new DeepNestingRulePhp(),
        new DeepNestingRuleDart(),
        new DeepNestingRuleRuby(),
        new DeepNestingRuleSwift(),
        new DeepNestingRuleCss(),
        new DeepNestingRuleHtml(),
        new DeepNestingRuleXml(),
        new DeepNestingRuleTerraform(),
        new DeepNestingRuleDockerfile(),
        new DeepNestingRuleKubernetes(),
        new DeepNestingRuleCloudFormation(),
        new DeepNestingRuleJson(),
        new MatchWithoutDefaultRuleJava(),
        new MatchWithoutDefaultRuleKotlin(),
        new MatchWithoutDefaultRuleJs(),
        new MatchWithoutDefaultRulePython(),
        new MatchWithoutDefaultRulePhp(),
        new MatchWithoutDefaultRuleGo(),
        new MatchWithoutDefaultRuleDart(),
        new MatchWithoutDefaultRuleRuby(),
        new MatchWithoutDefaultRuleSwift(),
        new MatchWithoutDefaultRuleCss(),
        new MatchWithoutDefaultRuleHtml(),
        new MatchWithoutDefaultRuleXml(),
        new MatchWithoutDefaultRuleTerraform(),
        new MatchWithoutDefaultRuleDockerfile(),
        new MatchWithoutDefaultRuleKubernetes(),
        new MatchWithoutDefaultRuleCloudFormation(),
        new MatchWithoutDefaultRuleJson(),
        new DuplicatedStringLiteralRuleCs(),
        new DuplicatedStringLiteralRuleJava(),
        new DuplicatedStringLiteralRuleJs(),
        new DuplicatedStringLiteralRulePython(),
        new DuplicatedStringLiteralRulePhp(),
        new DuplicatedStringLiteralRuleGo(),
        new DuplicatedStringLiteralRuleRuby(),
        new DuplicatedStringLiteralRuleSwift(),
        new DuplicatedStringLiteralRuleCss(),
        new DuplicatedStringLiteralRuleHtml(),
        new DuplicatedStringLiteralRuleXml(),
        new DuplicatedStringLiteralRuleTerraform(),
        new DuplicatedStringLiteralRuleDockerfile(),
        new DuplicatedStringLiteralRuleKubernetes(),
        new DuplicatedStringLiteralRuleCloudFormation(),
        new DuplicatedStringLiteralRuleJson(),
        new DuplicatedStringLiteralRuleKotlin(),
        new DuplicatedStringLiteralRuleDart(),
        new UnusedLocalVariableRuleCs(),
        new UnusedLocalVariableRuleJava(),
        new UnusedLocalVariableRuleJs(),
        new UnusedLocalVariableRulePython(),
        new UnusedLocalVariableRulePhp(),
        new UnusedLocalVariableRuleGo(),
        new UnusedLocalVariableRuleRuby(),
        new UnusedLocalVariableRuleSwift(),
        new UnusedLocalVariableRuleCss(),
        new UnusedLocalVariableRuleHtml(),
        new UnusedLocalVariableRuleXml(),
        new UnusedLocalVariableRuleTerraform(),
        new UnusedLocalVariableRuleDockerfile(),
        new UnusedLocalVariableRuleKubernetes(),
        new UnusedLocalVariableRuleCloudFormation(),
        new UnusedLocalVariableRuleJson(),
        new UnusedLocalVariableRuleKotlin(),
        new UnusedLocalVariableRuleDart(),
        new DeadStoreRuleCs(),
        new DeadStoreRuleJava(),
        new DeadStoreRuleJs(),
        new DeadStoreRulePython(),
        new DeadStoreRulePhp(),
        new DeadStoreRuleGo(),
        new DeadStoreRuleRuby(),
        new DeadStoreRuleSwift(),
        new DeadStoreRuleCss(),
        new DeadStoreRuleHtml(),
        new DeadStoreRuleXml(),
        new DeadStoreRuleTerraform(),
        new DeadStoreRuleDockerfile(),
        new DeadStoreRuleKubernetes(),
        new DeadStoreRuleCloudFormation(),
        new DeadStoreRuleJson(),
        new DeadStoreRuleKotlin(),
        new DeadStoreRuleDart(),
        new EmptyFunctionRuleCs(),
        new EmptyFunctionRuleJava(),
        new EmptyFunctionRuleJs(),
        new EmptyFunctionRulePython(),
        new EmptyFunctionRulePhp(),
        new EmptyFunctionRuleGo(),
        new EmptyFunctionRuleRuby(),
        new EmptyFunctionRuleSwift(),
        new EmptyFunctionRuleCss(),
        new EmptyFunctionRuleHtml(),
        new EmptyFunctionRuleXml(),
        new EmptyFunctionRuleTerraform(),
        new EmptyFunctionRuleDockerfile(),
        new EmptyFunctionRuleKubernetes(),
        new EmptyFunctionRuleCloudFormation(),
        new EmptyFunctionRuleJson(),
        new EmptyFunctionRuleKotlin(),
        new EmptyFunctionRuleDart(),
        new MultipleStatementsPerLineRuleJava(),
        new MultipleStatementsPerLineRulePython(),
        new MultipleStatementsPerLineRuleRuby(),
        new MultipleStatementsPerLineRuleSwift(),
        new MultipleStatementsPerLineRuleCss(),
        new MultipleStatementsPerLineRuleHtml(),
        new MultipleStatementsPerLineRuleXml(),
        new MultipleStatementsPerLineRuleTerraform(),
        new MultipleStatementsPerLineRuleDockerfile(),
        new MultipleStatementsPerLineRuleKubernetes(),
        new MultipleStatementsPerLineRuleCloudFormation(),
        new MultipleStatementsPerLineRuleJson(),
        new MultipleStatementsPerLineRuleKotlin(),
        new MultipleStatementsPerLineRuleDart(),
        new StringConcatenationInLoopRuleCs(),
        new StringConcatenationInLoopRuleJava(),
        new StringConcatenationInLoopRuleKotlin(),
        new StringConcatenationInLoopRuleJs(),
        new StringConcatenationInLoopRulePython(),
        new StringConcatenationInLoopRulePhp(),
        new StringConcatenationInLoopRuleGo(),
        new StringConcatenationInLoopRuleDart(),
        new StringConcatenationInLoopRuleRuby(),
        new StringConcatenationInLoopRuleSwift(),
        new StringConcatenationInLoopRuleCss(),
        new StringConcatenationInLoopRuleHtml(),
        new StringConcatenationInLoopRuleXml(),
        new StringConcatenationInLoopRuleTerraform(),
        new StringConcatenationInLoopRuleDockerfile(),
        new StringConcatenationInLoopRuleKubernetes(),
        new StringConcatenationInLoopRuleCloudFormation(),
        new StringConcatenationInLoopRuleJson(),
        new InvalidRegexRuleCs(),
        new InvalidRegexRuleJava(),
        new InvalidRegexRuleKotlin(),
        new InvalidRegexRuleJs(),
        new InvalidRegexRulePhp(),
        new InvalidRegexRuleGo(),
        new InvalidRegexRuleDart(),
        new InvalidRegexRuleRuby(),
        new InvalidRegexRuleSwift(),
        new InvalidRegexRuleCss(),
        new InvalidRegexRuleHtml(),
        new InvalidRegexRuleXml(),
        new InvalidRegexRuleTerraform(),
        new InvalidRegexRuleDockerfile(),
        new InvalidRegexRuleKubernetes(),
        new InvalidRegexRuleCloudFormation(),
        new InvalidRegexRuleJson(),
        new FileTooLongRuleCs(),
        new FileTooLongRuleJava(),
        new FileTooLongRuleKotlin(),
        new FileTooLongRuleJs(),
        new FileTooLongRulePython(),
        new FileTooLongRulePhp(),
        new FileTooLongRuleGo(),
        new FileTooLongRuleDart(),
        new FileTooLongRuleRuby(),
        new FileTooLongRuleSwift(),
        new FileTooLongRuleCss(),
        new FileTooLongRuleHtml(),
        new FileTooLongRuleXml(),
        new FileTooLongRuleTerraform(),
        new FileTooLongRuleDockerfile(),
        new FileTooLongRuleKubernetes(),
        new FileTooLongRuleCloudFormation(),
        new FileTooLongRuleJson(),
        new UnusedParameterRuleCs(),
        new UnusedParameterRuleJava(),
        new UnusedParameterRuleJs(),
        new UnusedParameterRulePython(),
        new UnusedParameterRulePhp(),
        new UnusedParameterRuleGo(),
        new UnusedParameterRuleRuby(),
        new UnusedParameterRuleSwift(),
        new UnusedParameterRuleCss(),
        new UnusedParameterRuleHtml(),
        new UnusedParameterRuleXml(),
        new UnusedParameterRuleTerraform(),
        new UnusedParameterRuleDockerfile(),
        new UnusedParameterRuleKubernetes(),
        new UnusedParameterRuleCloudFormation(),
        new UnusedParameterRuleJson(),
        new UnusedParameterRuleKotlin(),
        new UnusedParameterRuleDart(),
        new MergeableIfRuleCs(),
        new MergeableIfRuleJava(),
        new MergeableIfRuleKotlin(),
        new MergeableIfRuleJs(),
        new MergeableIfRulePython(),
        new MergeableIfRulePhp(),
        new MergeableIfRuleGo(),
        new MergeableIfRuleDart(),
        new MergeableIfRuleRuby(),
        new MergeableIfRuleSwift(),
        new MergeableIfRuleCss(),
        new MergeableIfRuleHtml(),
        new MergeableIfRuleXml(),
        new MergeableIfRuleTerraform(),
        new MergeableIfRuleDockerfile(),
        new MergeableIfRuleKubernetes(),
        new MergeableIfRuleCloudFormation(),
        new MergeableIfRuleJson(),
        new RedundantNestedBlockRuleCs(),
        new RedundantNestedBlockRuleJava(),
        new RedundantNestedBlockRuleKotlin(),
        new RedundantNestedBlockRuleJs(),
        new RedundantNestedBlockRulePython(),
        new RedundantNestedBlockRulePhp(),
        new RedundantNestedBlockRuleGo(),
        new RedundantNestedBlockRuleDart(),
        new RedundantNestedBlockRuleRuby(),
        new RedundantNestedBlockRuleSwift(),
        new RedundantNestedBlockRuleCss(),
        new RedundantNestedBlockRuleHtml(),
        new RedundantNestedBlockRuleXml(),
        new RedundantNestedBlockRuleTerraform(),
        new RedundantNestedBlockRuleDockerfile(),
        new RedundantNestedBlockRuleKubernetes(),
        new RedundantNestedBlockRuleCloudFormation(),
        new RedundantNestedBlockRuleJson(),
        new IfChainWithoutElseRuleJava(),
        new IfChainWithoutElseRuleJs(),
        new IfChainWithoutElseRulePython(),
        new IfChainWithoutElseRulePhp(),
        new IfChainWithoutElseRuleDart(),
        new IfChainWithoutElseRuleRuby(),
        new IfChainWithoutElseRuleSwift(),
        new IfChainWithoutElseRuleCss(),
        new IfChainWithoutElseRuleHtml(),
        new IfChainWithoutElseRuleXml(),
        new IfChainWithoutElseRuleTerraform(),
        new IfChainWithoutElseRuleDockerfile(),
        new IfChainWithoutElseRuleKubernetes(),
        new IfChainWithoutElseRuleCloudFormation(),
        new IfChainWithoutElseRuleJson(),
        new ComplexConditionRuleCs(),
        new ComplexConditionRuleJava(),
        new ComplexConditionRuleKotlin(),
        new ComplexConditionRuleJs(),
        new ComplexConditionRulePython(),
        new ComplexConditionRulePhp(),
        new ComplexConditionRuleGo(),
        new ComplexConditionRuleDart(),
        new ComplexConditionRuleRuby(),
        new ComplexConditionRuleSwift(),
        new ComplexConditionRuleCss(),
        new ComplexConditionRuleHtml(),
        new ComplexConditionRuleXml(),
        new ComplexConditionRuleTerraform(),
        new ComplexConditionRuleDockerfile(),
        new ComplexConditionRuleKubernetes(),
        new ComplexConditionRuleCloudFormation(),
        new ComplexConditionRuleJson(),
        new NestedMatchRuleCs(),
        new NestedMatchRuleJava(),
        new NestedMatchRuleKotlin(),
        new NestedMatchRuleJs(),
        new NestedMatchRulePython(),
        new NestedMatchRulePhp(),
        new NestedMatchRuleDart(),
        new NestedMatchRuleRuby(),
        new NestedMatchRuleSwift(),
        new NestedMatchRuleCss(),
        new NestedMatchRuleHtml(),
        new NestedMatchRuleXml(),
        new NestedMatchRuleTerraform(),
        new NestedMatchRuleDockerfile(),
        new NestedMatchRuleKubernetes(),
        new NestedMatchRuleCloudFormation(),
        new NestedMatchRuleJson(),
        new MissingBracesRuleCs(),
        new MissingBracesRuleJava(),
        new MissingBracesRuleKotlin(),
        new MissingBracesRuleJs(),
        new MissingBracesRulePython(),
        new MissingBracesRulePhp(),
        new MissingBracesRuleGo(),
        new MissingBracesRuleDart(),
        new MissingBracesRuleRuby(),
        new MissingBracesRuleSwift(),
        new MissingBracesRuleCss(),
        new MissingBracesRuleHtml(),
        new MissingBracesRuleXml(),
        new MissingBracesRuleTerraform(),
        new MissingBracesRuleDockerfile(),
        new MissingBracesRuleKubernetes(),
        new MissingBracesRuleCloudFormation(),
        new MissingBracesRuleJson(),
        new TooManyReturnsRuleCs(),
        new TooManyReturnsRuleJava(),
        new TooManyReturnsRuleKotlin(),
        new TooManyReturnsRuleJs(),
        new TooManyReturnsRulePython(),
        new TooManyReturnsRulePhp(),
        new TooManyReturnsRuleGo(),
        new TooManyReturnsRuleDart(),
        new TooManyReturnsRuleRuby(),
        new TooManyReturnsRuleSwift(),
        new TooManyReturnsRuleCss(),
        new TooManyReturnsRuleHtml(),
        new TooManyReturnsRuleXml(),
        new TooManyReturnsRuleTerraform(),
        new TooManyReturnsRuleDockerfile(),
        new TooManyReturnsRuleKubernetes(),
        new TooManyReturnsRuleCloudFormation(),
        new TooManyReturnsRuleJson(),
        new EmptyCatchRuleCs(),
        new EmptyCatchRuleJava(),
        new EmptyCatchRuleKotlin(),
        new EmptyCatchRuleJs(),
        new EmptyCatchRulePython(),
        new EmptyCatchRulePhp(),
        new EmptyCatchRuleGo(),
        new EmptyCatchRuleDart(),
        new EmptyCatchRuleRuby(),
        new EmptyCatchRuleSwift(),
        new EmptyCatchRuleCss(),
        new EmptyCatchRuleHtml(),
        new EmptyCatchRuleXml(),
        new EmptyCatchRuleTerraform(),
        new EmptyCatchRuleDockerfile(),
        new EmptyCatchRuleKubernetes(),
        new EmptyCatchRuleCloudFormation(),
        new EmptyCatchRuleJson(),
        new BooleanLiteralComparisonRuleCs(),
        new BooleanLiteralComparisonRuleJava(),
        new BooleanLiteralComparisonRuleKotlin(),
        new BooleanLiteralComparisonRuleJs(),
        new BooleanLiteralComparisonRulePython(),
        new BooleanLiteralComparisonRulePhp(),
        new BooleanLiteralComparisonRuleGo(),
        new BooleanLiteralComparisonRuleDart(),
        new BooleanLiteralComparisonRuleRuby(),
        new BooleanLiteralComparisonRuleSwift(),
        new BooleanLiteralComparisonRuleCss(),
        new BooleanLiteralComparisonRuleHtml(),
        new BooleanLiteralComparisonRuleXml(),
        new BooleanLiteralComparisonRuleTerraform(),
        new BooleanLiteralComparisonRuleDockerfile(),
        new BooleanLiteralComparisonRuleKubernetes(),
        new BooleanLiteralComparisonRuleCloudFormation(),
        new BooleanLiteralComparisonRuleJson(),
        new MagicNumberRuleJava(),
        new MagicNumberRulePython(),
        new MagicNumberRulePhp(),
        new MagicNumberRuleGo(),
        new MagicNumberRuleRuby(),
        new MagicNumberRuleSwift(),
        new MagicNumberRuleCss(),
        new MagicNumberRuleHtml(),
        new MagicNumberRuleXml(),
        new MagicNumberRuleTerraform(),
        new MagicNumberRuleDockerfile(),
        new MagicNumberRuleKubernetes(),
        new MagicNumberRuleCloudFormation(),
        new MagicNumberRuleJson(),
        new MagicNumberRuleKotlin(),
        new MagicNumberRuleDart(),
        new NestedTernaryRuleCs(),
        new NestedTernaryRuleJava(),
        new NestedTernaryRuleKotlin(),
        new NestedTernaryRuleJs(),
        new NestedTernaryRulePython(),
        new NestedTernaryRulePhp(),
        new NestedTernaryRuleGo(),
        new NestedTernaryRuleDart(),
        new NestedTernaryRuleRuby(),
        new NestedTernaryRuleSwift(),
        new NestedTernaryRuleCss(),
        new NestedTernaryRuleHtml(),
        new NestedTernaryRuleXml(),
        new NestedTernaryRuleTerraform(),
        new NestedTernaryRuleDockerfile(),
        new NestedTernaryRuleKubernetes(),
        new NestedTernaryRuleCloudFormation(),
        new NestedTernaryRuleJson(),
        new TooManyMembersRuleCs(),
        new TooManyMembersRuleJava(),
        new TooManyMembersRuleJs(),
        new TooManyMembersRulePython(),
        new TooManyMembersRulePhp(),
        new TooManyMembersRuleGo(),
        new TooManyMembersRuleRuby(),
        new TooManyMembersRuleSwift(),
        new TooManyMembersRuleCss(),
        new TooManyMembersRuleHtml(),
        new TooManyMembersRuleXml(),
        new TooManyMembersRuleTerraform(),
        new TooManyMembersRuleDockerfile(),
        new TooManyMembersRuleKubernetes(),
        new TooManyMembersRuleCloudFormation(),
        new TooManyMembersRuleJson(),
        new TooManyMembersRuleKotlin(),
        new TooManyMembersRuleDart(),
        new TestWithoutAssertionRuleCs(),
        new TestWithoutAssertionRuleJava(),
        new TestWithoutAssertionRuleKotlin(),
        new TestWithoutAssertionRuleJs(),
        new TestWithoutAssertionRulePython(),
        new TestWithoutAssertionRulePhp(),
        new TestWithoutAssertionRuleGo(),
        new TestWithoutAssertionRuleDart(),
        new TestWithoutAssertionRuleRuby(),
        new TestWithoutAssertionRuleSwift(),
        new TestWithoutAssertionRuleCss(),
        new TestWithoutAssertionRuleHtml(),
        new TestWithoutAssertionRuleXml(),
        new TestWithoutAssertionRuleTerraform(),
        new TestWithoutAssertionRuleDockerfile(),
        new TestWithoutAssertionRuleKubernetes(),
        new TestWithoutAssertionRuleCloudFormation(),
        new TestWithoutAssertionRuleJson(),
        new GenericExceptionCaughtRuleJava(),
        new GenericExceptionCaughtRuleKotlin(),
        new GenericExceptionCaughtRuleJs(),
        new GenericExceptionCaughtRulePython(),
        new GenericExceptionCaughtRulePhp(),
        new GenericExceptionCaughtRuleGo(),
        new GenericExceptionCaughtRuleDart(),
        new GenericExceptionCaughtRuleRuby(),
        new GenericExceptionCaughtRuleSwift(),
        new GenericExceptionCaughtRuleCss(),
        new GenericExceptionCaughtRuleHtml(),
        new GenericExceptionCaughtRuleXml(),
        new GenericExceptionCaughtRuleTerraform(),
        new GenericExceptionCaughtRuleDockerfile(),
        new GenericExceptionCaughtRuleKubernetes(),
        new GenericExceptionCaughtRuleCloudFormation(),
        new GenericExceptionCaughtRuleJson(),
        new GenericExceptionThrownRuleCs(),
        new GenericExceptionThrownRuleJava(),
        new GenericExceptionThrownRuleKotlin(),
        new GenericExceptionThrownRuleJs(),
        new GenericExceptionThrownRulePython(),
        new GenericExceptionThrownRulePhp(),
        new GenericExceptionThrownRuleGo(),
        new GenericExceptionThrownRuleDart(),
        new GenericExceptionThrownRuleRuby(),
        new GenericExceptionThrownRuleSwift(),
        new GenericExceptionThrownRuleCss(),
        new GenericExceptionThrownRuleHtml(),
        new GenericExceptionThrownRuleXml(),
        new GenericExceptionThrownRuleTerraform(),
        new GenericExceptionThrownRuleDockerfile(),
        new GenericExceptionThrownRuleKubernetes(),
        new GenericExceptionThrownRuleCloudFormation(),
        new GenericExceptionThrownRuleJson(),
        new RethrowLosingStackRuleCs(),
        new RethrowLosingStackRuleJava(),
        new RethrowLosingStackRuleKotlin(),
        new RethrowLosingStackRuleJs(),
        new RethrowLosingStackRulePython(),
        new RethrowLosingStackRulePhp(),
        new RethrowLosingStackRuleGo(),
        new RethrowLosingStackRuleDart(),
        new RethrowLosingStackRuleRuby(),
        new RethrowLosingStackRuleSwift(),
        new RethrowLosingStackRuleCss(),
        new RethrowLosingStackRuleHtml(),
        new RethrowLosingStackRuleXml(),
        new RethrowLosingStackRuleTerraform(),
        new RethrowLosingStackRuleDockerfile(),
        new RethrowLosingStackRuleKubernetes(),
        new RethrowLosingStackRuleCloudFormation(),
        new RethrowLosingStackRuleJson(),
        new JumpInFinallyRuleCs(),
        new JumpInFinallyRuleJava(),
        new JumpInFinallyRuleKotlin(),
        new JumpInFinallyRuleJs(),
        new JumpInFinallyRulePython(),
        new JumpInFinallyRulePhp(),
        new JumpInFinallyRuleGo(),
        new JumpInFinallyRuleDart(),
        new JumpInFinallyRuleRuby(),
        new JumpInFinallyRuleSwift(),
        new JumpInFinallyRuleCss(),
        new JumpInFinallyRuleHtml(),
        new JumpInFinallyRuleXml(),
        new JumpInFinallyRuleTerraform(),
        new JumpInFinallyRuleDockerfile(),
        new JumpInFinallyRuleKubernetes(),
        new JumpInFinallyRuleCloudFormation(),
        new JumpInFinallyRuleJson(),
        new LockOnSharedObjectRuleCs(),
        new LockOnSharedObjectRuleJava(),
        new LockOnSharedObjectRuleKotlin(),
        new LockOnSharedObjectRuleJs(),
        new LockOnSharedObjectRulePython(),
        new LockOnSharedObjectRulePhp(),
        new LockOnSharedObjectRuleGo(),
        new LockOnSharedObjectRuleDart(),
        new LockOnSharedObjectRuleRuby(),
        new LockOnSharedObjectRuleSwift(),
        new LockOnSharedObjectRuleCss(),
        new LockOnSharedObjectRuleHtml(),
        new LockOnSharedObjectRuleXml(),
        new LockOnSharedObjectRuleTerraform(),
        new LockOnSharedObjectRuleDockerfile(),
        new LockOnSharedObjectRuleKubernetes(),
        new LockOnSharedObjectRuleCloudFormation(),
        new LockOnSharedObjectRuleJson(),
        new IgnoredTestRuleCs(),
        new IgnoredTestRuleJava(),
        new IgnoredTestRuleKotlin(),
        new IgnoredTestRuleJs(),
        new IgnoredTestRulePython(),
        new IgnoredTestRulePhp(),
        new IgnoredTestRuleGo(),
        new IgnoredTestRuleDart(),
        new IgnoredTestRuleRuby(),
        new IgnoredTestRuleSwift(),
        new IgnoredTestRuleCss(),
        new IgnoredTestRuleHtml(),
        new IgnoredTestRuleXml(),
        new IgnoredTestRuleTerraform(),
        new IgnoredTestRuleDockerfile(),
        new IgnoredTestRuleKubernetes(),
        new IgnoredTestRuleCloudFormation(),
        new IgnoredTestRuleJson(),
        new UnusedPrivateFunctionRuleCs(),
        new UnusedPrivateFunctionRuleJava(),
        new UnusedPrivateFunctionRuleKotlin(),
        new UnusedPrivateFunctionRuleJs(),
        new UnusedPrivateFunctionRulePython(),
        new UnusedPrivateFunctionRulePhp(),
        new UnusedPrivateFunctionRuleGo(),
        new UnusedPrivateFunctionRuleDart(),
        new UnusedPrivateFunctionRuleRuby(),
        new UnusedPrivateFunctionRuleSwift(),
        new UnusedPrivateFunctionRuleCss(),
        new UnusedPrivateFunctionRuleHtml(),
        new UnusedPrivateFunctionRuleXml(),
        new UnusedPrivateFunctionRuleTerraform(),
        new UnusedPrivateFunctionRuleDockerfile(),
        new UnusedPrivateFunctionRuleKubernetes(),
        new UnusedPrivateFunctionRuleCloudFormation(),
        new UnusedPrivateFunctionRuleJson(),
        new RedundantJumpRuleCs(),
        new RedundantJumpRuleJava(),
        new RedundantJumpRuleKotlin(),
        new RedundantJumpRuleJs(),
        new RedundantJumpRulePython(),
        new RedundantJumpRulePhp(),
        new RedundantJumpRuleGo(),
        new RedundantJumpRuleDart(),
        new RedundantJumpRuleRuby(),
        new RedundantJumpRuleSwift(),
        new RedundantJumpRuleCss(),
        new RedundantJumpRuleHtml(),
        new RedundantJumpRuleXml(),
        new RedundantJumpRuleTerraform(),
        new RedundantJumpRuleDockerfile(),
        new RedundantJumpRuleKubernetes(),
        new RedundantJumpRuleCloudFormation(),
        new RedundantJumpRuleJson(),
        new CommentedOutCodeRuleCs(),
        new CommentedOutCodeRuleJava(),
        new CommentedOutCodeRuleKotlin(),
        new CommentedOutCodeRulePython(),
        new CommentedOutCodeRulePhp(),
        new CommentedOutCodeRuleGo(),
        new CommentedOutCodeRuleDart(),
        new CommentedOutCodeRuleRuby(),
        new CommentedOutCodeRuleSwift(),
        new CommentedOutCodeRuleCss(),
        new CommentedOutCodeRuleHtml(),
        new CommentedOutCodeRuleXml(),
        new CommentedOutCodeRuleTerraform(),
        new CommentedOutCodeRuleDockerfile(),
        new CommentedOutCodeRuleKubernetes(),
        new CommentedOutCodeRuleCloudFormation(),
        new CommentedOutCodeRuleJson(),
        new DeepInheritanceRuleCs(),
        new DeepInheritanceRuleJava(),
        new DeepInheritanceRuleKotlin(),
        new DeepInheritanceRuleJs(),
        new DeepInheritanceRulePython(),
        new DeepInheritanceRulePhp(),
        new DeepInheritanceRuleGo(),
        new DeepInheritanceRuleDart(),
        new DeepInheritanceRuleRuby(),
        new DeepInheritanceRuleSwift(),
        new DeepInheritanceRuleCss(),
        new DeepInheritanceRuleHtml(),
        new DeepInheritanceRuleXml(),
        new DeepInheritanceRuleTerraform(),
        new DeepInheritanceRuleDockerfile(),
        new DeepInheritanceRuleKubernetes(),
        new DeepInheritanceRuleCloudFormation(),
        new DeepInheritanceRuleJson(),
        new HiddenBaseMemberRuleCs(),
        new HiddenBaseMemberRuleJava(),
        new HiddenBaseMemberRuleKotlin(),
        new HiddenBaseMemberRuleJs(),
        new HiddenBaseMemberRulePython(),
        new HiddenBaseMemberRulePhp(),
        new HiddenBaseMemberRuleGo(),
        new HiddenBaseMemberRuleDart(),
        new HiddenBaseMemberRuleRuby(),
        new HiddenBaseMemberRuleSwift(),
        new HiddenBaseMemberRuleCss(),
        new HiddenBaseMemberRuleHtml(),
        new HiddenBaseMemberRuleXml(),
        new HiddenBaseMemberRuleTerraform(),
        new HiddenBaseMemberRuleDockerfile(),
        new HiddenBaseMemberRuleKubernetes(),
        new HiddenBaseMemberRuleCloudFormation(),
        new HiddenBaseMemberRuleJson(),
        new UnusedInternalMemberRuleCs(),
        new UnusedInternalMemberRuleJava(),
        new UnusedInternalMemberRuleKotlin(),
        new UnusedInternalMemberRuleJs(),
        new UnusedInternalMemberRulePython(),
        new UnusedInternalMemberRulePhp(),
        new UnusedInternalMemberRuleGo(),
        new UnusedInternalMemberRuleDart(),
        new UnusedInternalMemberRuleRuby(),
        new UnusedInternalMemberRuleSwift(),
        new UnusedInternalMemberRuleCss(),
        new UnusedInternalMemberRuleHtml(),
        new UnusedInternalMemberRuleXml(),
        new UnusedInternalMemberRuleTerraform(),
        new UnusedInternalMemberRuleDockerfile(),
        new UnusedInternalMemberRuleKubernetes(),
        new UnusedInternalMemberRuleCloudFormation(),
        new UnusedInternalMemberRuleJson(),
        new DuplicateTypeNameRuleCs(),
        new DuplicateTypeNameRuleJava(),
        new DuplicateTypeNameRuleKotlin(),
        new DuplicateTypeNameRuleJs(),
        new DuplicateTypeNameRulePython(),
        new DuplicateTypeNameRulePhp(),
        new DuplicateTypeNameRuleGo(),
        new DuplicateTypeNameRuleDart(),
        new DuplicateTypeNameRuleRuby(),
        new DuplicateTypeNameRuleSwift(),
        new DuplicateTypeNameRuleCss(),
        new DuplicateTypeNameRuleHtml(),
        new DuplicateTypeNameRuleXml(),
        new DuplicateTypeNameRuleTerraform(),
        new DuplicateTypeNameRuleDockerfile(),
        new DuplicateTypeNameRuleKubernetes(),
        new DuplicateTypeNameRuleCloudFormation(),
        new DuplicateTypeNameRuleJson(),
        new EqualityContractRuleCs(),
        new EqualityContractRuleJava(),
        new EqualityContractRuleKotlin(),
        new EqualityContractRuleJs(),
        new EqualityContractRulePython(),
        new EqualityContractRulePhp(),
        new EqualityContractRuleGo(),
        new EqualityContractRuleDart(),
        new EqualityContractRuleRuby(),
        new EqualityContractRuleSwift(),
        new EqualityContractRuleCss(),
        new EqualityContractRuleHtml(),
        new EqualityContractRuleXml(),
        new EqualityContractRuleTerraform(),
        new EqualityContractRuleDockerfile(),
        new EqualityContractRuleKubernetes(),
        new EqualityContractRuleCloudFormation(),
        new EqualityContractRuleJson(),
        new OverrideOnlyCallsBaseRuleCs(),
        new OverrideOnlyCallsBaseRuleJava(),
        new OverrideOnlyCallsBaseRuleKotlin(),
        new OverrideOnlyCallsBaseRuleJs(),
        new OverrideOnlyCallsBaseRulePython(),
        new OverrideOnlyCallsBaseRulePhp(),
        new OverrideOnlyCallsBaseRuleGo(),
        new OverrideOnlyCallsBaseRuleDart(),
        new OverrideOnlyCallsBaseRuleRuby(),
        new OverrideOnlyCallsBaseRuleSwift(),
        new OverrideOnlyCallsBaseRuleCss(),
        new OverrideOnlyCallsBaseRuleHtml(),
        new OverrideOnlyCallsBaseRuleXml(),
        new OverrideOnlyCallsBaseRuleTerraform(),
        new OverrideOnlyCallsBaseRuleDockerfile(),
        new OverrideOnlyCallsBaseRuleKubernetes(),
        new OverrideOnlyCallsBaseRuleCloudFormation(),
        new OverrideOnlyCallsBaseRuleJson(),
        new EmptyTypeRuleCs(),
        new EmptyTypeRuleJava(),
        new EmptyTypeRuleKotlin(),
        new EmptyTypeRuleJs(),
        new EmptyTypeRulePython(),
        new EmptyTypeRulePhp(),
        new EmptyTypeRuleGo(),
        new EmptyTypeRuleDart(),
        new EmptyTypeRuleRuby(),
        new EmptyTypeRuleSwift(),
        new EmptyTypeRuleCss(),
        new EmptyTypeRuleHtml(),
        new EmptyTypeRuleXml(),
        new EmptyTypeRuleTerraform(),
        new EmptyTypeRuleDockerfile(),
        new EmptyTypeRuleKubernetes(),
        new EmptyTypeRuleCloudFormation(),
        new EmptyTypeRuleJson(),
        new FieldCouldBeReadOnlyRuleCs(),
        new FieldCouldBeReadOnlyRuleJava(),
        new FieldCouldBeReadOnlyRuleKotlin(),
        new FieldCouldBeReadOnlyRuleJs(),
        new FieldCouldBeReadOnlyRulePython(),
        new FieldCouldBeReadOnlyRulePhp(),
        new FieldCouldBeReadOnlyRuleGo(),
        new FieldCouldBeReadOnlyRuleDart(),
        new FieldCouldBeReadOnlyRuleRuby(),
        new FieldCouldBeReadOnlyRuleSwift(),
        new FieldCouldBeReadOnlyRuleCss(),
        new FieldCouldBeReadOnlyRuleHtml(),
        new FieldCouldBeReadOnlyRuleXml(),
        new FieldCouldBeReadOnlyRuleTerraform(),
        new FieldCouldBeReadOnlyRuleDockerfile(),
        new FieldCouldBeReadOnlyRuleKubernetes(),
        new FieldCouldBeReadOnlyRuleCloudFormation(),
        new FieldCouldBeReadOnlyRuleJson(),
        new MethodCouldBeStaticRuleCs(),
        new MethodCouldBeStaticRuleJava(),
        new MethodCouldBeStaticRuleKotlin(),
        new MethodCouldBeStaticRuleJs(),
        new MethodCouldBeStaticRulePython(),
        new MethodCouldBeStaticRulePhp(),
        new MethodCouldBeStaticRuleGo(),
        new MethodCouldBeStaticRuleDart(),
        new MethodCouldBeStaticRuleRuby(),
        new MethodCouldBeStaticRuleSwift(),
        new MethodCouldBeStaticRuleCss(),
        new MethodCouldBeStaticRuleHtml(),
        new MethodCouldBeStaticRuleXml(),
        new MethodCouldBeStaticRuleTerraform(),
        new MethodCouldBeStaticRuleDockerfile(),
        new MethodCouldBeStaticRuleKubernetes(),
        new MethodCouldBeStaticRuleCloudFormation(),
        new MethodCouldBeStaticRuleJson(),
        new MutableStaticStateRuleCs(),
        new MutableStaticStateRuleJava(),
        new MutableStaticStateRuleKotlin(),
        new MutableStaticStateRuleJs(),
        new MutableStaticStateRulePython(),
        new MutableStaticStateRulePhp(),
        new MutableStaticStateRuleGo(),
        new MutableStaticStateRuleDart(),
        new MutableStaticStateRuleRuby(),
        new MutableStaticStateRuleSwift(),
        new MutableStaticStateRuleCss(),
        new MutableStaticStateRuleHtml(),
        new MutableStaticStateRuleXml(),
        new MutableStaticStateRuleTerraform(),
        new MutableStaticStateRuleDockerfile(),
        new MutableStaticStateRuleKubernetes(),
        new MutableStaticStateRuleCloudFormation(),
        new MutableStaticStateRuleJson(),
        new UnreleasedResourceRuleCs(),
        new UnreleasedResourceRuleJava(),
        new UnreleasedResourceRuleKotlin(),
        new UnreleasedResourceRuleJs(),
        new UnreleasedResourceRulePython(),
        new UnreleasedResourceRulePhp(),
        new UnreleasedResourceRuleGo(),
        new UnreleasedResourceRuleDart(),
        new UnreleasedResourceRuleRuby(),
        new UnreleasedResourceRuleSwift(),
        new UnreleasedResourceRuleCss(),
        new UnreleasedResourceRuleHtml(),
        new UnreleasedResourceRuleXml(),
        new UnreleasedResourceRuleTerraform(),
        new UnreleasedResourceRuleDockerfile(),
        new UnreleasedResourceRuleKubernetes(),
        new UnreleasedResourceRuleCloudFormation(),
        new UnreleasedResourceRuleJson(),
        new MismatchedComparisonRuleCs(),
        new MismatchedComparisonRuleRuby(),
        new MismatchedComparisonRuleSwift(),
        new MismatchedComparisonRuleCss(),
        new MismatchedComparisonRuleHtml(),
        new MismatchedComparisonRuleXml(),
        new MismatchedComparisonRuleTerraform(),
        new MismatchedComparisonRuleDockerfile(),
        new MismatchedComparisonRuleKubernetes(),
        new MismatchedComparisonRuleCloudFormation(),
        new MismatchedComparisonRuleJson(),
        new MismatchedComparisonRuleJava(),
        new MismatchedComparisonRuleKotlin(),
        new MismatchedComparisonRuleJs(),
        new MismatchedComparisonRulePython(),
        new MismatchedComparisonRulePhp(),
        new MismatchedComparisonRuleGo(),
        new MismatchedComparisonRuleDart()
    ];

    internal static string Normalized(SyntaxNode node)
        => string.Join(' ', node.Tokens.Where(t => t.Kind != TokenKind.Comment).Select(t => t.Text));
}

public abstract class StructuralRuleBase : RuleBase
{
    public override string[] Languages => [];

    /// <summary>Rules that depend on exact statement boundaries opt into this guard.</summary>
    protected static bool HasPreciseTree(IRuleContext context) => context.Tree.HasDedicatedParser;

    protected static IEnumerable<SyntaxNode> Blocks(IRuleContext context)
        => context.Root.OfKind(NodeKind.Block);

    protected static SyntaxNode? Condition(SyntaxNode branch)
        => branch.Children.FirstOrDefault(c => c.Kind is not (NodeKind.Block or NodeKind.ParameterList));
}

public abstract class UnreachableCodeAfterJumpRule : StructuralRuleBase
{
    public override string Name => "Statements after a jump are never executed";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "5min";

    // Not every keyword the parser files under Jump ends the flow. 'assert', 'del', 'pass',
    // 'global' and 'yield' carry on to the next statement, and treating them as terminators
    // reported the whole rest of the block as unreachable.
    private static bool LeavesTheBlock(string keyword) =>
        keyword is "return" or "raise" or "throw" or "break" or "continue" or "goto";

    public override void Execute(IRuleContext context)
    {
        foreach (var block in Blocks(context))
        {
            var children = block.Children;
            for (var i = 0; i < children.Count - 1; i++)
            {
                if (children[i].Kind != NodeKind.Jump || !LeavesTheBlock(children[i].Text))
                    continue;
                var next = children[i + 1];
                if (next.Kind is NodeKind.MatchCase or NodeKind.Else or NodeKind.Catch or NodeKind.Finally)
                    continue;
                // A block opening on the same line as the jump is its argument, not code stranded
                // behind it: 'return withSession { ... }' in Kotlin, and every trailing lambda.
                if (next.Kind == NodeKind.Block && next.Range.StartLine == children[i].Range.StartLine)
                    continue;
                context.Report(next, $"This code is unreachable: '{children[i].Text}' on line "
                                     + $"{children[i].Line} always leaves the block first.");
                break;
            }
        }
    }
}

public sealed class UnreachableCodeAfterJumpRuleCs : UnreachableCodeAfterJumpRule
{
    public override string Key => "QG-CS-BUG-0150";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class UnreachableCodeAfterJumpRuleJava : UnreachableCodeAfterJumpRule
{
    public override string Key => "QG-JV-BUG-0204";
    public override string[] Languages => ["java"];
}

public sealed class UnreachableCodeAfterJumpRuleKotlin : UnreachableCodeAfterJumpRule
{
    public override string Key => "QG-KT-BUG-0031";
    public override string[] Languages => ["kt"];
}

public sealed class UnreachableCodeAfterJumpRuleJs : UnreachableCodeAfterJumpRule
{
    public override string Key => "QG-JS-BUG-0148";
    public override string[] Languages => ["js", "ts"];
}

public sealed class UnreachableCodeAfterJumpRulePython : UnreachableCodeAfterJumpRule
{
    public override string Key => "QG-PY-BUG-0154";
    public override string[] Languages => ["py"];
}

public sealed class UnreachableCodeAfterJumpRulePhp : UnreachableCodeAfterJumpRule
{
    public override string Key => "QG-PP-BUG-0051";
    public override string[] Languages => ["php"];
}

public sealed class UnreachableCodeAfterJumpRuleGo : UnreachableCodeAfterJumpRule
{
    public override string Key => "QG-GO-BUG-0007";
    public override string[] Languages => ["go"];
}

public sealed class UnreachableCodeAfterJumpRuleDart : UnreachableCodeAfterJumpRule
{
    public override string Key => "QG-DART-BUG-0005";
    public override string[] Languages => ["dart"];
}

public sealed class UnreachableCodeAfterJumpRuleRuby : UnreachableCodeAfterJumpRule
{
    public override string Key => "QG-RB-BUG-0025";
    public override string[] Languages => ["rb"];
}

public sealed class UnreachableCodeAfterJumpRuleSwift : UnreachableCodeAfterJumpRule
{
    public override string Key => "QG-SW-BUG-0029";
    public override string[] Languages => ["swift"];
}

public sealed class UnreachableCodeAfterJumpRuleCss : UnreachableCodeAfterJumpRule
{
    public override string Key => "QG-CSS-BUG-0054";
    public override string[] Languages => ["css"];
}

public sealed class UnreachableCodeAfterJumpRuleHtml : UnreachableCodeAfterJumpRule
{
    public override string Key => "QG-HTML-BUG-0054";
    public override string[] Languages => ["html"];
}

public sealed class UnreachableCodeAfterJumpRuleXml : UnreachableCodeAfterJumpRule
{
    public override string Key => "QG-XML-BUG-0029";
    public override string[] Languages => ["xml"];
}

public sealed class UnreachableCodeAfterJumpRuleTerraform : UnreachableCodeAfterJumpRule
{
    public override string Key => "QG-TF-BUG-0024";
    public override string[] Languages => ["tf"];
}

public sealed class UnreachableCodeAfterJumpRuleDockerfile : UnreachableCodeAfterJumpRule
{
    public override string Key => "QG-DK-BUG-0031";
    public override string[] Languages => ["dk"];
}

public sealed class UnreachableCodeAfterJumpRuleKubernetes : UnreachableCodeAfterJumpRule
{
    public override string Key => "QG-K8-BUG-0024";
    public override string[] Languages => ["k8"];
}

public sealed class UnreachableCodeAfterJumpRuleCloudFormation : UnreachableCodeAfterJumpRule
{
    public override string Key => "QG-CF-BUG-0024";
    public override string[] Languages => ["cf"];
}

public sealed class UnreachableCodeAfterJumpRuleJson : UnreachableCodeAfterJumpRule
{
    public override string Key => "QG-JSON-BUG-0025";
    public override string[] Languages => ["json"];
}

public abstract class DuplicateConditionRule : StructuralRuleBase
{
    public override string Name => "A condition should not be repeated in the same branch chain";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        foreach (var head in context.Root.OfKind(NodeKind.If))
        {
            if (head.Parent?.Kind == NodeKind.Else || IsElseIf(head))
                continue; // only the head of a chain drives the comparison

            var seen = new Dictionary<string, int>(StringComparer.Ordinal);
            foreach (var branch in Chain(head))
            {
                if (Condition(branch) is not { } condition)
                    continue;
                var text = StructuralRuleSet.Normalized(condition);
                if (text.Length == 0)
                    continue;
                if (seen.TryGetValue(text, out var firstLine))
                    context.Report(condition, $"This condition repeats the one on line {firstLine}, "
                                              + "so this branch can never run.");
                else
                    seen[text] = condition.Line;
            }
        }
    }

    internal static bool IsElseIf(SyntaxNode branch)
        => branch.Ancestors().Take(2).Any(a => a.Kind == NodeKind.Else);

    /// <summary>The if and every else-if that continues it.</summary>
    internal static IEnumerable<SyntaxNode> Chain(SyntaxNode head)
    {
        var current = head;
        while (current != null)
        {
            yield return current;
            current = NextBranch(current);
        }
    }

    internal static SyntaxNode? NextBranch(SyntaxNode branch)
    {
        var elseNode = branch.FirstChild(NodeKind.Else);
        if (elseNode == null)
            return null;
        var body = elseNode.FirstChild(NodeKind.Block);
        if (body is { Children.Count: 1 } && body.Children[0].Kind == NodeKind.If)
            return body.Children[0];
        return null;
    }

    internal static SyntaxNode? FinalElse(SyntaxNode head)
    {
        var last = Chain(head).Last();
        var elseNode = last.FirstChild(NodeKind.Else);
        return elseNode;
    }
}

public sealed class DuplicateConditionRuleCs : DuplicateConditionRule
{
    public override string Key => "QG-CS-BUG-0151";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class DuplicateConditionRuleJava : DuplicateConditionRule
{
    public override string Key => "QG-JV-BUG-0205";
    public override string[] Languages => ["java"];
}

public sealed class DuplicateConditionRuleKotlin : DuplicateConditionRule
{
    public override string Key => "QG-KT-BUG-0032";
    public override string[] Languages => ["kt"];
}

public sealed class DuplicateConditionRuleJs : DuplicateConditionRule
{
    public override string Key => "QG-JS-BUG-0149";
    public override string[] Languages => ["js", "ts"];
}

public sealed class DuplicateConditionRulePython : DuplicateConditionRule
{
    public override string Key => "QG-PY-BUG-0155";
    public override string[] Languages => ["py"];
}

public sealed class DuplicateConditionRulePhp : DuplicateConditionRule
{
    public override string Key => "QG-PP-BUG-0052";
    public override string[] Languages => ["php"];
}

public sealed class DuplicateConditionRuleGo : DuplicateConditionRule
{
    public override string Key => "QG-GO-BUG-0008";
    public override string[] Languages => ["go"];
}

public sealed class DuplicateConditionRuleDart : DuplicateConditionRule
{
    public override string Key => "QG-DART-BUG-0006";
    public override string[] Languages => ["dart"];
}

public sealed class DuplicateConditionRuleRuby : DuplicateConditionRule
{
    public override string Key => "QG-RB-BUG-0026";
    public override string[] Languages => ["rb"];
}

public sealed class DuplicateConditionRuleSwift : DuplicateConditionRule
{
    public override string Key => "QG-SW-BUG-0030";
    public override string[] Languages => ["swift"];
}

public sealed class DuplicateConditionRuleCss : DuplicateConditionRule
{
    public override string Key => "QG-CSS-BUG-0055";
    public override string[] Languages => ["css"];
}

public sealed class DuplicateConditionRuleHtml : DuplicateConditionRule
{
    public override string Key => "QG-HTML-BUG-0055";
    public override string[] Languages => ["html"];
}

public sealed class DuplicateConditionRuleXml : DuplicateConditionRule
{
    public override string Key => "QG-XML-BUG-0030";
    public override string[] Languages => ["xml"];
}

public sealed class DuplicateConditionRuleTerraform : DuplicateConditionRule
{
    public override string Key => "QG-TF-BUG-0025";
    public override string[] Languages => ["tf"];
}

public sealed class DuplicateConditionRuleDockerfile : DuplicateConditionRule
{
    public override string Key => "QG-DK-BUG-0032";
    public override string[] Languages => ["dk"];
}

public sealed class DuplicateConditionRuleKubernetes : DuplicateConditionRule
{
    public override string Key => "QG-K8-BUG-0025";
    public override string[] Languages => ["k8"];
}

public sealed class DuplicateConditionRuleCloudFormation : DuplicateConditionRule
{
    public override string Key => "QG-CF-BUG-0025";
    public override string[] Languages => ["cf"];
}

public sealed class DuplicateConditionRuleJson : DuplicateConditionRule
{
    public override string Key => "QG-JSON-BUG-0026";
    public override string[] Languages => ["json"];
}

public abstract class ConstantConditionRule : StructuralRuleBase
{
    public override string Name => "Conditions should not always evaluate to the same result";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        foreach (var branch in context.Root.OfKind(NodeKind.If, NodeKind.Loop))
        {
            if (Condition(branch) is not { } condition)
                continue;
            var expression = Unwrap(condition);
            if (expression.Kind == NodeKind.BooleanLiteral)
            {
                if (branch.Kind == NodeKind.Loop && expression.Text is "true" or "True")
                    continue; // an intentional infinite loop
                context.Report(condition, $"This condition is always {expression.Text.ToLowerInvariant()}, "
                                          + "so the branch it guards is not a decision.");
                continue;
            }
            if (expression.Kind == NodeKind.Binary && expression.Text is "&&" or "||" or "and" or "or"
                && expression.Children.Any(c => Unwrap(c).Kind == NodeKind.BooleanLiteral))
                context.Report(condition, "A boolean literal in this condition fixes its result: "
                                          + "the other operand is never taken into account.");
        }
    }

    private static SyntaxNode Unwrap(SyntaxNode node)
        => node.Kind is NodeKind.Parenthesized && node.Children.Count == 1 ? Unwrap(node.Children[0]) : node;
}

public sealed class ConstantConditionRuleCs : ConstantConditionRule
{
    public override string Key => "QG-CS-BUG-0152";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class ConstantConditionRuleJava : ConstantConditionRule
{
    public override string Key => "QG-JV-BUG-0206";
    public override string[] Languages => ["java"];
}

public sealed class ConstantConditionRuleKotlin : ConstantConditionRule
{
    public override string Key => "QG-KT-BUG-0033";
    public override string[] Languages => ["kt"];
}

public sealed class ConstantConditionRuleJs : ConstantConditionRule
{
    public override string Key => "QG-JS-BUG-0150";
    public override string[] Languages => ["js", "ts"];
}

public sealed class ConstantConditionRulePython : ConstantConditionRule
{
    public override string Key => "QG-PY-BUG-0156";
    public override string[] Languages => ["py"];
}

public sealed class ConstantConditionRulePhp : ConstantConditionRule
{
    public override string Key => "QG-PP-BUG-0053";
    public override string[] Languages => ["php"];
}

public sealed class ConstantConditionRuleGo : ConstantConditionRule
{
    public override string Key => "QG-GO-BUG-0009";
    public override string[] Languages => ["go"];
}

public sealed class ConstantConditionRuleDart : ConstantConditionRule
{
    public override string Key => "QG-DART-BUG-0007";
    public override string[] Languages => ["dart"];
}

public sealed class ConstantConditionRuleRuby : ConstantConditionRule
{
    public override string Key => "QG-RB-BUG-0027";
    public override string[] Languages => ["rb"];
}

public sealed class ConstantConditionRuleSwift : ConstantConditionRule
{
    public override string Key => "QG-SW-BUG-0031";
    public override string[] Languages => ["swift"];
}

public sealed class ConstantConditionRuleCss : ConstantConditionRule
{
    public override string Key => "QG-CSS-BUG-0056";
    public override string[] Languages => ["css"];
}

public sealed class ConstantConditionRuleHtml : ConstantConditionRule
{
    public override string Key => "QG-HTML-BUG-0056";
    public override string[] Languages => ["html"];
}

public sealed class ConstantConditionRuleXml : ConstantConditionRule
{
    public override string Key => "QG-XML-BUG-0031";
    public override string[] Languages => ["xml"];
}

public sealed class ConstantConditionRuleTerraform : ConstantConditionRule
{
    public override string Key => "QG-TF-BUG-0026";
    public override string[] Languages => ["tf"];
}

public sealed class ConstantConditionRuleDockerfile : ConstantConditionRule
{
    public override string Key => "QG-DK-BUG-0033";
    public override string[] Languages => ["dk"];
}

public sealed class ConstantConditionRuleKubernetes : ConstantConditionRule
{
    public override string Key => "QG-K8-BUG-0026";
    public override string[] Languages => ["k8"];
}

public sealed class ConstantConditionRuleCloudFormation : ConstantConditionRule
{
    public override string Key => "QG-CF-BUG-0026";
    public override string[] Languages => ["cf"];
}

public sealed class ConstantConditionRuleJson : ConstantConditionRule
{
    public override string Key => "QG-JSON-BUG-0027";
    public override string[] Languages => ["json"];
}

public abstract class SelfAssignmentRule : StructuralRuleBase
{
    public override string Name => "A variable should not be assigned to itself";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        foreach (var assignment in context.Root.OfKind(NodeKind.Assignment))
        {
            if (assignment.Text != "=")
                continue;
            // a declaration is not a self-assignment, whatever its initializer is called
            // 'new Thing { Id = Id }' sets a member of the object being built from a variable that
            // happens to share its name. The two sides are different things, and reading them as one
            // reported every object initialiser written against a matching parameter name.
            if (assignment.Ancestor(NodeKind.ObjectCreation, NodeKind.ListLiteral,
                    NodeKind.ArrayCreation, NodeKind.Attribute) != null)
                continue;
            // A named argument reads the same way — 'type = type' passes the local 'type' to the
            // parameter called 'type', which is the ordinary shape wherever named arguments exist.
            // The two sides live in different places and only look alike.
            if (assignment.Ancestor(NodeKind.ArgumentList, NodeKind.NamedArgument) != null)
                continue;
            if (assignment.Parent is { Kind: NodeKind.VariableDeclaration or NodeKind.FieldDeclaration })
                continue;

            var left = PlainName(assignment.ChildAt(0));
            var right = PlainName(assignment.ChildAt(1));
            if (left.Length > 0 && left == right)
                context.Report(assignment, $"Assigning '{left}' to itself has no effect; "
                                           + "the intended target or source is probably a different name.");
        }
    }

    /// <summary>
    /// The dotted name of a node when it is nothing but identifiers joined by dots. A call, a cast
    /// or an index gives an empty answer: 'boolean isSubscribed = isSubscribed(tree)' names the same
    /// thing on both sides and is not an assignment to itself.
    /// </summary>
    private static string PlainName(SyntaxNode? node)
    {
        if (node == null)
            return string.Empty;
        if (node.Kind == NodeKind.Identifier)
            return node.Text;
        if (node.Kind != NodeKind.MemberSelect)
            return string.Empty;

        foreach (var part in node.DescendantsAndSelf())
        {
            if (part.Kind is not (NodeKind.MemberSelect or NodeKind.Identifier))
                return string.Empty;
        }
        return SyntaxQuery.DottedName(node);
    }
}

public sealed class SelfAssignmentRuleCs : SelfAssignmentRule
{
    public override string Key => "QG-CS-BUG-0153";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class SelfAssignmentRuleJava : SelfAssignmentRule
{
    public override string Key => "QG-JV-BUG-0207";
    public override string[] Languages => ["java"];
}

public sealed class SelfAssignmentRuleKotlin : SelfAssignmentRule
{
    public override string Key => "QG-KT-BUG-0034";
    public override string[] Languages => ["kt"];
}

public sealed class SelfAssignmentRuleJs : SelfAssignmentRule
{
    public override string Key => "QG-JS-BUG-0151";
    public override string[] Languages => ["js", "ts"];
}

public sealed class SelfAssignmentRulePython : SelfAssignmentRule
{
    public override string Key => "QG-PY-BUG-0157";
    public override string[] Languages => ["py"];
}

public sealed class SelfAssignmentRulePhp : SelfAssignmentRule
{
    public override string Key => "QG-PP-BUG-0054";
    public override string[] Languages => ["php"];
}

public sealed class SelfAssignmentRuleGo : SelfAssignmentRule
{
    public override string Key => "QG-GO-BUG-0010";
    public override string[] Languages => ["go"];
}

public sealed class SelfAssignmentRuleDart : SelfAssignmentRule
{
    public override string Key => "QG-DART-BUG-0008";
    public override string[] Languages => ["dart"];
}

public sealed class SelfAssignmentRuleRuby : SelfAssignmentRule
{
    public override string Key => "QG-RB-BUG-0028";
    public override string[] Languages => ["rb"];
}

public sealed class SelfAssignmentRuleSwift : SelfAssignmentRule
{
    public override string Key => "QG-SW-BUG-0032";
    public override string[] Languages => ["swift"];
}

public sealed class SelfAssignmentRuleCss : SelfAssignmentRule
{
    public override string Key => "QG-CSS-BUG-0057";
    public override string[] Languages => ["css"];
}

public sealed class SelfAssignmentRuleHtml : SelfAssignmentRule
{
    public override string Key => "QG-HTML-BUG-0057";
    public override string[] Languages => ["html"];
}

public sealed class SelfAssignmentRuleXml : SelfAssignmentRule
{
    public override string Key => "QG-XML-BUG-0032";
    public override string[] Languages => ["xml"];
}

public sealed class SelfAssignmentRuleTerraform : SelfAssignmentRule
{
    public override string Key => "QG-TF-BUG-0027";
    public override string[] Languages => ["tf"];
}

public sealed class SelfAssignmentRuleDockerfile : SelfAssignmentRule
{
    public override string Key => "QG-DK-BUG-0034";
    public override string[] Languages => ["dk"];
}

public sealed class SelfAssignmentRuleKubernetes : SelfAssignmentRule
{
    public override string Key => "QG-K8-BUG-0027";
    public override string[] Languages => ["k8"];
}

public sealed class SelfAssignmentRuleCloudFormation : SelfAssignmentRule
{
    public override string Key => "QG-CF-BUG-0027";
    public override string[] Languages => ["cf"];
}

public sealed class SelfAssignmentRuleJson : SelfAssignmentRule
{
    public override string Key => "QG-JSON-BUG-0028";
    public override string[] Languages => ["json"];
}

public abstract class IdenticalOperandsRule : StructuralRuleBase
{
    private static readonly string[] Operators =
        ["==", "!=", "===", "!==", "<", ">", "<=", ">=", "&&", "||", "and", "or", "-", "/", "%"];
    public override string Name => "Both operands of an operator should not be identical";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        foreach (var binary in context.Root.OfKind(NodeKind.Binary))
        {
            if (!Operators.Contains(binary.Text, StringComparer.Ordinal))
                continue;
            var left = binary.ChildAt(0);
            var right = binary.ChildAt(1);
            if (left == null || right == null)
                continue;
            var leftText = StructuralRuleSet.Normalized(left);
            if (leftText.Length == 0 || leftText != StructuralRuleSet.Normalized(right))
                continue;
            if (leftText.Contains('(')) // a repeated call may legitimately return different values
                continue;
            context.Report(binary, $"'{leftText}' appears on both sides of '{binary.Text}', "
                                   + "which makes the result constant.");
        }
    }
}

public sealed class IdenticalOperandsRuleCs : IdenticalOperandsRule
{
    public override string Key => "QG-CS-BUG-0154";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class IdenticalOperandsRuleJava : IdenticalOperandsRule
{
    public override string Key => "QG-JV-BUG-0208";
    public override string[] Languages => ["java"];
}

public sealed class IdenticalOperandsRuleKotlin : IdenticalOperandsRule
{
    public override string Key => "QG-KT-BUG-0035";
    public override string[] Languages => ["kt"];
}

public sealed class IdenticalOperandsRuleJs : IdenticalOperandsRule
{
    public override string Key => "QG-JS-BUG-0152";
    public override string[] Languages => ["js", "ts"];
}

public sealed class IdenticalOperandsRulePython : IdenticalOperandsRule
{
    public override string Key => "QG-PY-BUG-0158";
    public override string[] Languages => ["py"];
}

public sealed class IdenticalOperandsRulePhp : IdenticalOperandsRule
{
    public override string Key => "QG-PP-BUG-0055";
    public override string[] Languages => ["php"];
}

public sealed class IdenticalOperandsRuleGo : IdenticalOperandsRule
{
    public override string Key => "QG-GO-BUG-0011";
    public override string[] Languages => ["go"];
}

public sealed class IdenticalOperandsRuleDart : IdenticalOperandsRule
{
    public override string Key => "QG-DART-BUG-0009";
    public override string[] Languages => ["dart"];
}

public sealed class IdenticalOperandsRuleRuby : IdenticalOperandsRule
{
    public override string Key => "QG-RB-BUG-0029";
    public override string[] Languages => ["rb"];
}

public sealed class IdenticalOperandsRuleSwift : IdenticalOperandsRule
{
    public override string Key => "QG-SW-BUG-0033";
    public override string[] Languages => ["swift"];
}

public sealed class IdenticalOperandsRuleCss : IdenticalOperandsRule
{
    public override string Key => "QG-CSS-BUG-0058";
    public override string[] Languages => ["css"];
}

public sealed class IdenticalOperandsRuleHtml : IdenticalOperandsRule
{
    public override string Key => "QG-HTML-BUG-0058";
    public override string[] Languages => ["html"];
}

public sealed class IdenticalOperandsRuleXml : IdenticalOperandsRule
{
    public override string Key => "QG-XML-BUG-0033";
    public override string[] Languages => ["xml"];
}

public sealed class IdenticalOperandsRuleTerraform : IdenticalOperandsRule
{
    public override string Key => "QG-TF-BUG-0028";
    public override string[] Languages => ["tf"];
}

public sealed class IdenticalOperandsRuleDockerfile : IdenticalOperandsRule
{
    public override string Key => "QG-DK-BUG-0035";
    public override string[] Languages => ["dk"];
}

public sealed class IdenticalOperandsRuleKubernetes : IdenticalOperandsRule
{
    public override string Key => "QG-K8-BUG-0028";
    public override string[] Languages => ["k8"];
}

public sealed class IdenticalOperandsRuleCloudFormation : IdenticalOperandsRule
{
    public override string Key => "QG-CF-BUG-0028";
    public override string[] Languages => ["cf"];
}

public sealed class IdenticalOperandsRuleJson : IdenticalOperandsRule
{
    public override string Key => "QG-JSON-BUG-0029";
    public override string[] Languages => ["json"];
}

public abstract class IdenticalBranchesRule : StructuralRuleBase
{
    public override string Name => "Branches of a conditional should not have the same body";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        foreach (var branch in context.Root.OfKind(NodeKind.If))
        {
            var body = branch.FirstChild(NodeKind.Block);
            var otherwise = branch.FirstChild(NodeKind.Else)?.FirstChild(NodeKind.Block);
            if (body == null || otherwise == null || body.Children.Count == 0)
                continue;
            if (otherwise.Children.Count == 1 && otherwise.Children[0].Kind == NodeKind.If)
                continue; // an else-if chain, not a duplicated branch
            if (StructuralRuleSet.Normalized(body) != StructuralRuleSet.Normalized(otherwise))
                continue;
            context.Report(otherwise, $"This branch does exactly what the branch on line {body.Line} does, "
                                      + "so the condition changes nothing.");
        }
    }
}

public sealed class IdenticalBranchesRuleCs : IdenticalBranchesRule
{
    public override string Key => "QG-CS-BUG-0155";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class IdenticalBranchesRuleJava : IdenticalBranchesRule
{
    public override string Key => "QG-JV-BUG-0209";
    public override string[] Languages => ["java"];
}

public sealed class IdenticalBranchesRuleKotlin : IdenticalBranchesRule
{
    public override string Key => "QG-KT-BUG-0036";
    public override string[] Languages => ["kt"];
}

public sealed class IdenticalBranchesRuleJs : IdenticalBranchesRule
{
    public override string Key => "QG-JS-BUG-0153";
    public override string[] Languages => ["js", "ts"];
}

public sealed class IdenticalBranchesRulePython : IdenticalBranchesRule
{
    public override string Key => "QG-PY-BUG-0159";
    public override string[] Languages => ["py"];
}

public sealed class IdenticalBranchesRulePhp : IdenticalBranchesRule
{
    public override string Key => "QG-PP-BUG-0056";
    public override string[] Languages => ["php"];
}

public sealed class IdenticalBranchesRuleGo : IdenticalBranchesRule
{
    public override string Key => "QG-GO-BUG-0012";
    public override string[] Languages => ["go"];
}

public sealed class IdenticalBranchesRuleDart : IdenticalBranchesRule
{
    public override string Key => "QG-DART-BUG-0010";
    public override string[] Languages => ["dart"];
}

public sealed class IdenticalBranchesRuleRuby : IdenticalBranchesRule
{
    public override string Key => "QG-RB-BUG-0030";
    public override string[] Languages => ["rb"];
}

public sealed class IdenticalBranchesRuleSwift : IdenticalBranchesRule
{
    public override string Key => "QG-SW-BUG-0034";
    public override string[] Languages => ["swift"];
}

public sealed class IdenticalBranchesRuleCss : IdenticalBranchesRule
{
    public override string Key => "QG-CSS-BUG-0059";
    public override string[] Languages => ["css"];
}

public sealed class IdenticalBranchesRuleHtml : IdenticalBranchesRule
{
    public override string Key => "QG-HTML-BUG-0059";
    public override string[] Languages => ["html"];
}

public sealed class IdenticalBranchesRuleXml : IdenticalBranchesRule
{
    public override string Key => "QG-XML-BUG-0034";
    public override string[] Languages => ["xml"];
}

public sealed class IdenticalBranchesRuleTerraform : IdenticalBranchesRule
{
    public override string Key => "QG-TF-BUG-0029";
    public override string[] Languages => ["tf"];
}

public sealed class IdenticalBranchesRuleDockerfile : IdenticalBranchesRule
{
    public override string Key => "QG-DK-BUG-0036";
    public override string[] Languages => ["dk"];
}

public sealed class IdenticalBranchesRuleKubernetes : IdenticalBranchesRule
{
    public override string Key => "QG-K8-BUG-0029";
    public override string[] Languages => ["k8"];
}

public sealed class IdenticalBranchesRuleCloudFormation : IdenticalBranchesRule
{
    public override string Key => "QG-CF-BUG-0029";
    public override string[] Languages => ["cf"];
}

public sealed class IdenticalBranchesRuleJson : IdenticalBranchesRule
{
    public override string Key => "QG-JSON-BUG-0030";
    public override string[] Languages => ["json"];
}

public abstract class TooManyParametersRule : StructuralRuleBase
{
    private const int Max = 7;
    public override string Name => "Functions should not take too many parameters";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "20min";

    public override void Execute(IRuleContext context)
    {
        foreach (var function in SyntaxQuery.Functions(context.Root))
        {
            var count = SyntaxQuery.Parameters(function).Count();
            if (count <= Max)
                continue;

            // the cost follows the size of the problem: every parameter past the limit is another
            // one to find a home for, and every caller has to be changed with it
            context.ReportCosting($"'{function.Text}' takes {count} parameters (limit is {Max}); "
                                  + "group the related ones into an object.",
                20 + (count - Max) * 10, function.Line);
        }
    }
}

public sealed class TooManyParametersRuleCs : TooManyParametersRule
{
    public override string Key => "QG-CS-SML-0505";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class TooManyParametersRuleJava : TooManyParametersRule
{
    public override string Key => "QG-JV-SML-0466";
    public override string[] Languages => ["java"];
}

public sealed class TooManyParametersRuleKotlin : TooManyParametersRule
{
    public override string Key => "QG-KT-SML-0088";
    public override string[] Languages => ["kt"];
}

public sealed class TooManyParametersRuleJs : TooManyParametersRule
{
    public override string Key => "QG-JS-SML-0382";
    public override string[] Languages => ["js", "ts"];
}

public sealed class TooManyParametersRulePython : TooManyParametersRule
{
    public override string Key => "QG-PY-SML-0261";
    public override string[] Languages => ["py"];
}

public sealed class TooManyParametersRulePhp : TooManyParametersRule
{
    public override string Key => "QG-PP-SML-0126";
    public override string[] Languages => ["php"];
}

public sealed class TooManyParametersRuleGo : TooManyParametersRule
{
    public override string Key => "QG-GO-SML-0040";
    public override string[] Languages => ["go"];
}

public sealed class TooManyParametersRuleDart : TooManyParametersRule
{
    public override string Key => "QG-DART-SML-0005";
    public override string[] Languages => ["dart"];
}

public sealed class TooManyParametersRuleRuby : TooManyParametersRule
{
    public override string Key => "QG-RB-SML-0032";
    public override string[] Languages => ["rb"];
}

public sealed class TooManyParametersRuleSwift : TooManyParametersRule
{
    public override string Key => "QG-SW-SML-0016";
    public override string[] Languages => ["swift"];
}

public sealed class TooManyParametersRuleCss : TooManyParametersRule
{
    public override string Key => "QG-CSS-SML-0037";
    public override string[] Languages => ["css"];
}

public sealed class TooManyParametersRuleHtml : TooManyParametersRule
{
    public override string Key => "QG-HTML-SML-0109";
    public override string[] Languages => ["html"];
}

public sealed class TooManyParametersRuleXml : TooManyParametersRule
{
    public override string Key => "QG-XML-SML-0024";
    public override string[] Languages => ["xml"];
}

public sealed class TooManyParametersRuleTerraform : TooManyParametersRule
{
    public override string Key => "QG-TF-SML-0016";
    public override string[] Languages => ["tf"];
}

public sealed class TooManyParametersRuleDockerfile : TooManyParametersRule
{
    public override string Key => "QG-DK-SML-0030";
    public override string[] Languages => ["dk"];
}

public sealed class TooManyParametersRuleKubernetes : TooManyParametersRule
{
    public override string Key => "QG-K8-SML-0024";
    public override string[] Languages => ["k8"];
}

public sealed class TooManyParametersRuleCloudFormation : TooManyParametersRule
{
    public override string Key => "QG-CF-SML-0017";
    public override string[] Languages => ["cf"];
}

public sealed class TooManyParametersRuleJson : TooManyParametersRule
{
    public override string Key => "QG-JSON-SML-0012";
    public override string[] Languages => ["json"];
}

public abstract class FunctionTooLongRule : StructuralRuleBase
{
    private const int MaxLines = 120;
    public override string Name => "Functions should not be too long";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "30min";

    public override void Execute(IRuleContext context)
    {
        foreach (var function in SyntaxQuery.Functions(context.Root))
        {
            var body = SyntaxQuery.Body(function);
            var length = (body ?? function).Range.LineCount;
            if (length <= MaxLines)
                continue;

            context.ReportCosting($"'{function.Text}' is {length} lines long (limit is {MaxLines}); "
                                  + "split the steps it performs into separate functions.",
                30 + (length - MaxLines) / 20 * 10, function.Line);
        }
    }
}

public sealed class FunctionTooLongRuleCs : FunctionTooLongRule
{
    public override string Key => "QG-CS-SML-0506";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class FunctionTooLongRuleJava : FunctionTooLongRule
{
    public override string Key => "QG-JV-SML-0467";
    public override string[] Languages => ["java"];
}

public sealed class FunctionTooLongRuleKotlin : FunctionTooLongRule
{
    public override string Key => "QG-KT-SML-0089";
    public override string[] Languages => ["kt"];
}

public sealed class FunctionTooLongRuleJs : FunctionTooLongRule
{
    public override string Key => "QG-JS-SML-0383";
    public override string[] Languages => ["js", "ts"];
}

public sealed class FunctionTooLongRulePython : FunctionTooLongRule
{
    public override string Key => "QG-PY-SML-0262";
    public override string[] Languages => ["py"];
}

public sealed class FunctionTooLongRulePhp : FunctionTooLongRule
{
    public override string Key => "QG-PP-SML-0127";
    public override string[] Languages => ["php"];
}

public sealed class FunctionTooLongRuleGo : FunctionTooLongRule
{
    public override string Key => "QG-GO-SML-0041";
    public override string[] Languages => ["go"];
}

public sealed class FunctionTooLongRuleDart : FunctionTooLongRule
{
    public override string Key => "QG-DART-SML-0006";
    public override string[] Languages => ["dart"];
}

public sealed class FunctionTooLongRuleRuby : FunctionTooLongRule
{
    public override string Key => "QG-RB-SML-0033";
    public override string[] Languages => ["rb"];
}

public sealed class FunctionTooLongRuleSwift : FunctionTooLongRule
{
    public override string Key => "QG-SW-SML-0017";
    public override string[] Languages => ["swift"];
}

public sealed class FunctionTooLongRuleCss : FunctionTooLongRule
{
    public override string Key => "QG-CSS-SML-0038";
    public override string[] Languages => ["css"];
}

public sealed class FunctionTooLongRuleHtml : FunctionTooLongRule
{
    public override string Key => "QG-HTML-SML-0110";
    public override string[] Languages => ["html"];
}

public sealed class FunctionTooLongRuleXml : FunctionTooLongRule
{
    public override string Key => "QG-XML-SML-0025";
    public override string[] Languages => ["xml"];
}

public sealed class FunctionTooLongRuleTerraform : FunctionTooLongRule
{
    public override string Key => "QG-TF-SML-0017";
    public override string[] Languages => ["tf"];
}

public sealed class FunctionTooLongRuleDockerfile : FunctionTooLongRule
{
    public override string Key => "QG-DK-SML-0031";
    public override string[] Languages => ["dk"];
}

public sealed class FunctionTooLongRuleKubernetes : FunctionTooLongRule
{
    public override string Key => "QG-K8-SML-0025";
    public override string[] Languages => ["k8"];
}

public sealed class FunctionTooLongRuleCloudFormation : FunctionTooLongRule
{
    public override string Key => "QG-CF-SML-0018";
    public override string[] Languages => ["cf"];
}

public sealed class FunctionTooLongRuleJson : FunctionTooLongRule
{
    public override string Key => "QG-JSON-SML-0013";
    public override string[] Languages => ["json"];
}

public abstract class CognitiveComplexityRule : StructuralRuleBase
{
    private const int Max = 15;
    public override string Name => "Functions should not be too hard to follow";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "30min";

    public override void Execute(IRuleContext context)
    {
        foreach (var function in SyntaxQuery.Functions(context.Root))
        {
            var score = MetricCalculator.CognitiveComplexity(function, 0);
            if (score <= Max)
                continue;

            // a function three times over the limit is not three times the work of one a point over
            // it, but it is not the same work either: the cost grows with the distance
            context.ReportCosting($"'{function.Text}' scores {score} on nesting-aware complexity "
                                  + $"(limit is {Max}); flatten the branches or extract the inner logic.",
                30 + (score - Max), function.Line);
        }
    }
}

public sealed class CognitiveComplexityRuleCs : CognitiveComplexityRule
{
    public override string Key => "QG-CS-SML-0500";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class CognitiveComplexityRuleJava : CognitiveComplexityRule
{
    public override string Key => "QG-JV-SML-0461";
    public override string[] Languages => ["java"];
}

public sealed class CognitiveComplexityRuleJs : CognitiveComplexityRule
{
    public override string Key => "QG-JS-SML-0377";
    public override string[] Languages => ["js", "ts"];
}

public sealed class CognitiveComplexityRulePython : CognitiveComplexityRule
{
    public override string Key => "QG-PY-SML-0256";
    public override string[] Languages => ["py"];
}

public sealed class CognitiveComplexityRulePhp : CognitiveComplexityRule
{
    public override string Key => "QG-PP-SML-0121";
    public override string[] Languages => ["php"];
}

public sealed class CognitiveComplexityRuleGo : CognitiveComplexityRule
{
    public override string Key => "QG-GO-SML-0035";
    public override string[] Languages => ["go"];
}

public sealed class CognitiveComplexityRuleRuby : CognitiveComplexityRule
{
    public override string Key => "QG-RB-SML-0034";
    public override string[] Languages => ["rb"];
}

public sealed class CognitiveComplexityRuleSwift : CognitiveComplexityRule
{
    public override string Key => "QG-SW-SML-0018";
    public override string[] Languages => ["swift"];
}

public sealed class CognitiveComplexityRuleCss : CognitiveComplexityRule
{
    public override string Key => "QG-CSS-SML-0039";
    public override string[] Languages => ["css"];
}

public sealed class CognitiveComplexityRuleHtml : CognitiveComplexityRule
{
    public override string Key => "QG-HTML-SML-0111";
    public override string[] Languages => ["html"];
}

public sealed class CognitiveComplexityRuleXml : CognitiveComplexityRule
{
    public override string Key => "QG-XML-SML-0026";
    public override string[] Languages => ["xml"];
}

public sealed class CognitiveComplexityRuleTerraform : CognitiveComplexityRule
{
    public override string Key => "QG-TF-SML-0018";
    public override string[] Languages => ["tf"];
}

public sealed class CognitiveComplexityRuleDockerfile : CognitiveComplexityRule
{
    public override string Key => "QG-DK-SML-0032";
    public override string[] Languages => ["dk"];
}

public sealed class CognitiveComplexityRuleKubernetes : CognitiveComplexityRule
{
    public override string Key => "QG-K8-SML-0026";
    public override string[] Languages => ["k8"];
}

public sealed class CognitiveComplexityRuleCloudFormation : CognitiveComplexityRule
{
    public override string Key => "QG-CF-SML-0019";
    public override string[] Languages => ["cf"];
}

public sealed class CognitiveComplexityRuleJson : CognitiveComplexityRule
{
    public override string Key => "QG-JSON-SML-0014";
    public override string[] Languages => ["json"];
}

public sealed class CognitiveComplexityRuleKotlin : CognitiveComplexityRule
{
    public override string Key => "QG-KT-SML-0129";
    public override string[] Languages => ["kt"];
}

public sealed class CognitiveComplexityRuleDart : CognitiveComplexityRule
{
    public override string Key => "QG-DART-SML-0047";
    public override string[] Languages => ["dart"];
}

public abstract class DeepNestingRule : StructuralRuleBase
{
    private const int Max = 4;
    public override string Name => "Control structures should not be nested too deeply";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "20min";

    public override void Execute(IRuleContext context)
    {
        foreach (var function in SyntaxQuery.Functions(context.Root))
        {
            var deepest = function.Descendants()
                .Where(n => n.Kind is NodeKind.If or NodeKind.Loop or NodeKind.Match or NodeKind.Try)
                .Select(n => (Node: n, Depth: SyntaxQuery.NestingDepth(n) + 1))
                .Where(x => x.Depth > Max)
                .OrderByDescending(x => x.Depth)
                .FirstOrDefault();
            if (deepest.Node != null)
                context.Report(deepest.Node, $"This block sits {deepest.Depth} levels deep (limit is {Max}); "
                                             + "return early or extract the inner levels into a function.");
        }
    }
}

public sealed class DeepNestingRuleCs : DeepNestingRule
{
    public override string Key => "QG-CS-SML-0507";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class DeepNestingRuleJava : DeepNestingRule
{
    public override string Key => "QG-JV-SML-0468";
    public override string[] Languages => ["java"];
}

public sealed class DeepNestingRuleKotlin : DeepNestingRule
{
    public override string Key => "QG-KT-SML-0090";
    public override string[] Languages => ["kt"];
}

public sealed class DeepNestingRuleJs : DeepNestingRule
{
    public override string Key => "QG-JS-SML-0384";
    public override string[] Languages => ["js", "ts"];
}

public sealed class DeepNestingRulePython : DeepNestingRule
{
    public override string Key => "QG-PY-SML-0263";
    public override string[] Languages => ["py"];
}

public sealed class DeepNestingRulePhp : DeepNestingRule
{
    public override string Key => "QG-PP-SML-0128";
    public override string[] Languages => ["php"];
}

public sealed class DeepNestingRuleGo : DeepNestingRule
{
    public override string Key => "QG-GO-SML-0042";
    public override string[] Languages => ["go"];
}

public sealed class DeepNestingRuleDart : DeepNestingRule
{
    public override string Key => "QG-DART-SML-0007";
    public override string[] Languages => ["dart"];
}

public sealed class DeepNestingRuleRuby : DeepNestingRule
{
    public override string Key => "QG-RB-SML-0035";
    public override string[] Languages => ["rb"];
}

public sealed class DeepNestingRuleSwift : DeepNestingRule
{
    public override string Key => "QG-SW-SML-0019";
    public override string[] Languages => ["swift"];
}

public sealed class DeepNestingRuleCss : DeepNestingRule
{
    public override string Key => "QG-CSS-SML-0040";
    public override string[] Languages => ["css"];
}

public sealed class DeepNestingRuleHtml : DeepNestingRule
{
    public override string Key => "QG-HTML-SML-0112";
    public override string[] Languages => ["html"];
}

public sealed class DeepNestingRuleXml : DeepNestingRule
{
    public override string Key => "QG-XML-SML-0027";
    public override string[] Languages => ["xml"];
}

public sealed class DeepNestingRuleTerraform : DeepNestingRule
{
    public override string Key => "QG-TF-SML-0019";
    public override string[] Languages => ["tf"];
}

public sealed class DeepNestingRuleDockerfile : DeepNestingRule
{
    public override string Key => "QG-DK-SML-0033";
    public override string[] Languages => ["dk"];
}

public sealed class DeepNestingRuleKubernetes : DeepNestingRule
{
    public override string Key => "QG-K8-SML-0027";
    public override string[] Languages => ["k8"];
}

public sealed class DeepNestingRuleCloudFormation : DeepNestingRule
{
    public override string Key => "QG-CF-SML-0020";
    public override string[] Languages => ["cf"];
}

public sealed class DeepNestingRuleJson : DeepNestingRule
{
    public override string Key => "QG-JSON-SML-0015";
    public override string[] Languages => ["json"];
}

public abstract class MatchWithoutDefaultRule : StructuralRuleBase
{
    public override string Name => "Multi-way branches should handle the unexpected value";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        foreach (var match in context.Root.OfKind(NodeKind.Match))
        {
            var body = match.FirstChild(NodeKind.Block);
            if (body == null || body.Children.Count == 0)
                continue;
            var hasDefault = body.DescendantsAndSelf()
                .Any(n => n.Tokens.Count > 0 && n.Tokens[0].Text is "default" or "else" or "_");
            if (!hasDefault)
                context.Report(match, "No branch handles the values that are not listed; add a default case "
                                      + "so an unexpected value is not silently ignored.");
        }
    }
}

public sealed class MatchWithoutDefaultRuleCs : MatchWithoutDefaultRule
{
    public override string Key => "QG-CS-SML-0508";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class MatchWithoutDefaultRuleJava : MatchWithoutDefaultRule
{
    public override string Key => "QG-JV-SML-0469";
    public override string[] Languages => ["java"];
}

public sealed class MatchWithoutDefaultRuleKotlin : MatchWithoutDefaultRule
{
    public override string Key => "QG-KT-SML-0091";
    public override string[] Languages => ["kt"];
}

public sealed class MatchWithoutDefaultRuleJs : MatchWithoutDefaultRule
{
    public override string Key => "QG-JS-SML-0385";
    public override string[] Languages => ["js", "ts"];
}

public sealed class MatchWithoutDefaultRulePython : MatchWithoutDefaultRule
{
    public override string Key => "QG-PY-SML-0264";
    public override string[] Languages => ["py"];
}

public sealed class MatchWithoutDefaultRulePhp : MatchWithoutDefaultRule
{
    public override string Key => "QG-PP-SML-0129";
    public override string[] Languages => ["php"];
}

public sealed class MatchWithoutDefaultRuleGo : MatchWithoutDefaultRule
{
    public override string Key => "QG-GO-SML-0043";
    public override string[] Languages => ["go"];
}

public sealed class MatchWithoutDefaultRuleDart : MatchWithoutDefaultRule
{
    public override string Key => "QG-DART-SML-0008";
    public override string[] Languages => ["dart"];
}

public sealed class MatchWithoutDefaultRuleRuby : MatchWithoutDefaultRule
{
    public override string Key => "QG-RB-SML-0036";
    public override string[] Languages => ["rb"];
}

public sealed class MatchWithoutDefaultRuleSwift : MatchWithoutDefaultRule
{
    public override string Key => "QG-SW-SML-0020";
    public override string[] Languages => ["swift"];
}

public sealed class MatchWithoutDefaultRuleCss : MatchWithoutDefaultRule
{
    public override string Key => "QG-CSS-SML-0041";
    public override string[] Languages => ["css"];
}

public sealed class MatchWithoutDefaultRuleHtml : MatchWithoutDefaultRule
{
    public override string Key => "QG-HTML-SML-0113";
    public override string[] Languages => ["html"];
}

public sealed class MatchWithoutDefaultRuleXml : MatchWithoutDefaultRule
{
    public override string Key => "QG-XML-SML-0028";
    public override string[] Languages => ["xml"];
}

public sealed class MatchWithoutDefaultRuleTerraform : MatchWithoutDefaultRule
{
    public override string Key => "QG-TF-SML-0020";
    public override string[] Languages => ["tf"];
}

public sealed class MatchWithoutDefaultRuleDockerfile : MatchWithoutDefaultRule
{
    public override string Key => "QG-DK-SML-0034";
    public override string[] Languages => ["dk"];
}

public sealed class MatchWithoutDefaultRuleKubernetes : MatchWithoutDefaultRule
{
    public override string Key => "QG-K8-SML-0028";
    public override string[] Languages => ["k8"];
}

public sealed class MatchWithoutDefaultRuleCloudFormation : MatchWithoutDefaultRule
{
    public override string Key => "QG-CF-SML-0021";
    public override string[] Languages => ["cf"];
}

public sealed class MatchWithoutDefaultRuleJson : MatchWithoutDefaultRule
{
    public override string Key => "QG-JSON-SML-0016";
    public override string[] Languages => ["json"];
}

public abstract class DuplicatedStringLiteralRule : StructuralRuleBase
{
    private const int Threshold = 3;

    /// <summary>
    /// Short strings are repeated everywhere and naming them buys nothing: a constant called
    /// SLASH holding "/" is worse than the slash. The advice starts paying at about this length.
    /// </summary>
    private const int MinLength = 10;

    /// <summary>Calls whose string argument names a module, not a value that could be a constant.</summary>
    private static readonly string[] ModuleReferences =
        ["require", "import", "define", "mock", "unmock", "doMock", "jest.mock", "importScripts"];
    public override string Name => "String literals should not be duplicated";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";

    /// <summary>
    /// Formats with nowhere to put a constant. A repeated value in JSON, in a template or in a
    /// stylesheet is how those files are written, and there is no declaration to move it to.
    /// </summary>
    private static readonly string[] NoConstants =
        ["json", "yaml", "yml", "xml", "csv", "html", "raz", "razor", "cshtml", "vbhtml", "vue",
         "css", "scss", "sass", "less", "md", "txt", "resx", "config", "sql"];

    public override void Execute(IRuleContext context)
    {
        if (NoConstants.Contains(context.Language.LanguageKey, StringComparer.OrdinalIgnoreCase))
            return;

        var modules = ModuleNames(context);
        var groups = context.Root.OfKind(NodeKind.StringLiteral)
            .Where(l => Nameable(l.Text) && !modules.Contains(l.Text))
            .GroupBy(l => l.Text, StringComparer.Ordinal)
            .Where(g => g.Count() >= Threshold);

        foreach (var group in groups)
        {
            var first = group.First();
            context.Report(first, $"This literal is repeated {group.Count()} times; "
                                  + "declare it once as a constant and reference it.");
        }
    }

    /// <summary>
    /// Whether a literal is the kind of thing a constant can be given a name for: long enough to be
    /// worth naming, and made of words rather than punctuation or a number.
    /// </summary>
    private static bool Nameable(string text)
    {
        var trimmed = text.Trim();
        if (trimmed.Length < MinLength || !trimmed.Any(char.IsLetter))
            return false;

        // A literal made of nothing but word characters is a name — a key, an identifier, an
        // encoding — and naming a name twice buys nothing. So is a format skeleton, and so is a
        // colour. Reporting those three was most of what this rule said on a Python project.
        if (trimmed.All(c => char.IsLetterOrDigit(c) || c is '_' or '-'))
            return false;
        if (trimmed.All(c => char.IsDigit(c) || "{} .-_%:dfrsymhYMHS<>".Contains(c)))
            return false;
        if (trimmed.Length == 7 && trimmed[0] == '#'
            && trimmed[1..].All(Uri.IsHexDigit))
            return false;

        return true;
    }

    /// <summary>
    /// The module names the file mentions. Repeating one is how imports are written, and replacing it
    /// with a constant would break the tools that read those calls statically.
    /// </summary>
    private static HashSet<string> ModuleNames(IRuleContext context)
    {
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            var invoked = SyntaxQuery.InvokedName(call);
            var dotted = SyntaxQuery.InvokedDottedName(call);
            if (!ModuleReferences.Contains(invoked, StringComparer.Ordinal)
                && !ModuleReferences.Contains(dotted, StringComparer.Ordinal))
                continue;
            if (SyntaxQuery.ArgumentAt(call, 0) is { Kind: NodeKind.StringLiteral } module)
                names.Add(module.Text);
        }
        return names;
    }
}

public sealed class DuplicatedStringLiteralRuleCs : DuplicatedStringLiteralRule
{
    public override string Key => "QG-CS-SML-0496";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class DuplicatedStringLiteralRuleJava : DuplicatedStringLiteralRule
{
    public override string Key => "QG-JV-SML-0457";
    public override string[] Languages => ["java"];
}

public sealed class DuplicatedStringLiteralRuleJs : DuplicatedStringLiteralRule
{
    public override string Key => "QG-JS-SML-0373";
    public override string[] Languages => ["js", "ts"];
}

public sealed class DuplicatedStringLiteralRulePython : DuplicatedStringLiteralRule
{
    public override string Key => "QG-PY-SML-0252";
    public override string[] Languages => ["py"];
}

public sealed class DuplicatedStringLiteralRulePhp : DuplicatedStringLiteralRule
{
    public override string Key => "QG-PP-SML-0117";
    public override string[] Languages => ["php"];
}

public sealed class DuplicatedStringLiteralRuleGo : DuplicatedStringLiteralRule
{
    public override string Key => "QG-GO-SML-0031";
    public override string[] Languages => ["go"];
}

public sealed class DuplicatedStringLiteralRuleRuby : DuplicatedStringLiteralRule
{
    public override string Key => "QG-RB-SML-0037";
    public override string[] Languages => ["rb"];
}

public sealed class DuplicatedStringLiteralRuleSwift : DuplicatedStringLiteralRule
{
    public override string Key => "QG-SW-SML-0021";
    public override string[] Languages => ["swift"];
}

public sealed class DuplicatedStringLiteralRuleCss : DuplicatedStringLiteralRule
{
    public override string Key => "QG-CSS-SML-0042";
    public override string[] Languages => ["css"];
}

public sealed class DuplicatedStringLiteralRuleHtml : DuplicatedStringLiteralRule
{
    public override string Key => "QG-HTML-SML-0114";
    public override string[] Languages => ["html"];
}

public sealed class DuplicatedStringLiteralRuleXml : DuplicatedStringLiteralRule
{
    public override string Key => "QG-XML-SML-0029";
    public override string[] Languages => ["xml"];
}

public sealed class DuplicatedStringLiteralRuleTerraform : DuplicatedStringLiteralRule
{
    public override string Key => "QG-TF-SML-0021";
    public override string[] Languages => ["tf"];
}

public sealed class DuplicatedStringLiteralRuleDockerfile : DuplicatedStringLiteralRule
{
    public override string Key => "QG-DK-SML-0035";
    public override string[] Languages => ["dk"];
}

public sealed class DuplicatedStringLiteralRuleKubernetes : DuplicatedStringLiteralRule
{
    public override string Key => "QG-K8-SML-0029";
    public override string[] Languages => ["k8"];
}

public sealed class DuplicatedStringLiteralRuleCloudFormation : DuplicatedStringLiteralRule
{
    public override string Key => "QG-CF-SML-0022";
    public override string[] Languages => ["cf"];
}

public sealed class DuplicatedStringLiteralRuleJson : DuplicatedStringLiteralRule
{
    public override string Key => "QG-JSON-SML-0017";
    public override string[] Languages => ["json"];
}

public sealed class DuplicatedStringLiteralRuleKotlin : DuplicatedStringLiteralRule
{
    public override string Key => "QG-KT-SML-0130";
    public override string[] Languages => ["kt"];
}

public sealed class DuplicatedStringLiteralRuleDart : DuplicatedStringLiteralRule
{
    public override string Key => "QG-DART-SML-0048";
    public override string[] Languages => ["dart"];
}

public abstract class DeadStoreRule : StructuralRuleBase
{
    public override string Name => "A value should be read before it is replaced";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var symbol in context.Semantics.AllSymbols())
        {
            if (symbol.Scope.Kind is not (ScopeKind.Function or ScopeKind.Block) || symbol.IsParameter)
                continue;
            // a dotted name is a member of another object: it outlives the statement and is read
            // through the name of the object, which this rule cannot follow
            if (symbol.Name.StartsWith('_') || symbol.Name.Contains('.'))
                continue;

            var usages = symbol.Usages
                .Where(u => u.Kind is UsageKind.Declaration or UsageKind.Assignment or UsageKind.Reference)
                .OrderBy(u => u.Line)
                .ToList();

            // a value written and never read again before the name goes out of scope is dead too,
            // and that is the commoner shape: the assignment is left over from a change
            var last = usages.Count > 0 ? usages[^1] : null;
            if (last is { Kind: UsageKind.Assignment }
                && !InsideInitializer(last.Identifier) && !SetsAMember(last.Identifier)
                && !ReadAgainNextTimeRound(last.Identifier, symbol.Name)
                && usages.Any(u => u.Kind == UsageKind.Reference)
                && last.Value is { } written
                && !written.DescendantsAndSelf().Any(n => n.Kind == NodeKind.Identifier && n.Text == symbol.Name))
            {
                context.Report(last.Identifier, $"'{symbol.Name}' is given a value here that nothing "
                                                + "reads afterwards. Either the assignment is left "
                                                + "over, or the code that was meant to use it is.");
                continue;
            }

            for (var i = 0; i < usages.Count - 1; i++)
            {
                var write = usages[i];
                if (write.Kind == UsageKind.Reference)
                    continue;
                var next = usages[i + 1];
                if (next.Kind == UsageKind.Reference)
                    continue;

                // Two writes with no read between them mean the first value never mattered — but
                // only when both are on the same straight line of code. Across a branch the earlier
                // write is the value the other path uses, and reporting it would be wrong.
                if (!SameStraightLine(write.Identifier, next.Identifier))
                    continue;
                // a declaration with no value written is not a store
                if (write.Kind == UsageKind.Declaration && write.Value == null)
                    continue;
                // 'new Thing { Name = "a" }' assigns a member of the object being built, not a
                // variable: two initialisers naming the same member are two different objects
                if (InsideInitializer(write.Identifier) || InsideInitializer(next.Identifier))
                    continue;
                if (SetsAMember(write.Identifier) || SetsAMember(next.Identifier))
                    continue;
                // 'ret = ret.Where(...)' reads the value it replaces, so the first store mattered
                if (next.Value != null && next.Value.DescendantsAndSelf()
                        .Any(n => n.Kind == NodeKind.Identifier && n.Text == symbol.Name))
                    continue;

                context.Report(write.Identifier, $"The value put in '{symbol.Name}' here is replaced on "
                                                 + $"line {next.Line} without ever being read. Either "
                                                 + "this assignment is left over, or the one that "
                                                 + "reads it was lost.");
                break;
            }
        }
    }

    /// <summary>
    /// Whether the write sets a member of another object — 'filter.Page = 2' — rather than a local.
    /// The object outlives the statement and is read through its own name, which this rule cannot
    /// follow.
    /// </summary>
    /// <summary>Scope functions whose block writes to the receiver rather than to a local.</summary>
    private static readonly string[] ReceiverBlocks = ["apply", "also", "run", "with", "let"];

    private static bool SetsAMember(SyntaxNode identifier)
    {
        if (identifier.Parent?.Kind == NodeKind.MemberSelect)
            return true;

        // Inside 'apply { pingInterval = ... }' the bare name is a property of the object the block
        // was given, not a local of the enclosing function. Reading it as a local made every builder
        // written in that style look like a value assigned and dropped.
        for (var node = identifier.Parent; node != null; node = node.Parent)
        {
            if (node.Kind is NodeKind.FunctionDeclaration or NodeKind.ClassDeclaration)
                break;
            if (node.Kind != NodeKind.Lambda)
                continue;
            var call = node.Ancestor(NodeKind.Invocation);
            if (call != null
                && ReceiverBlocks.Contains(SyntaxQuery.InvokedName(call), StringComparer.Ordinal))
                return true;
        }
        return false;
    }

    /// <summary>Whether the write sets a member of an object being constructed.</summary>
    /// <summary>
    /// Whether a write inside a loop is read on the following pass. The last write in program order
    /// is not the last write in execution order: 'index += 1' at the foot of a while body, or
    /// 'text = stripped' inside a for, is read at the top of the next iteration. Reading the usage
    /// list in line order alone called both of those dead.
    /// </summary>
    private static bool ReadAgainNextTimeRound(SyntaxNode write, string name)
    {
        for (var node = write.Parent; node != null; node = node.Parent)
        {
            if (node.Kind is not (NodeKind.Loop or NodeKind.Match))
                continue;
            var readsInside = node.DescendantsAndSelf()
                .Any(n => n.Kind == NodeKind.Identifier && n.Text == name
                          && n != write && !IsWrittenAt(n));
            if (readsInside)
                return true;
        }
        return false;
    }

    /// <summary>Whether this appearance of a name is the left-hand side of an assignment.</summary>
    private static bool IsWrittenAt(SyntaxNode identifier)
    {
        var parent = identifier.Parent;
        if (parent is { Kind: NodeKind.Index or NodeKind.MemberSelect })
            parent = parent.Parent;
        return parent is { Kind: NodeKind.Assignment }
               && parent.ChildAt(0) is { } left
               && left.DescendantsAndSelf().Contains(identifier);
    }

    private static bool InsideInitializer(SyntaxNode node)
    {
        for (var parent = node.Parent; parent != null; parent = parent.Parent)
        {
            // an object initialiser, a collection literal, and the named argument of an attribute:
            // in none of them is the left-hand side a variable with a lifetime of its own
            if (parent.Kind is NodeKind.ObjectCreation or NodeKind.ListLiteral or NodeKind.ArrayCreation
                or NodeKind.Attribute or NodeKind.AttributeList or NodeKind.ArgumentList)
                return true;
            if (parent.Kind is NodeKind.Block or NodeKind.FunctionDeclaration)
                return false;
        }
        return false;
    }

    /// <summary>
    /// Whether two writes run one after the other with nothing choosing between them: same block, and
    /// no branch or loop in between that either of them sits inside.
    /// </summary>
    private static bool SameStraightLine(SyntaxNode first, SyntaxNode second)
    {
        var firstBlock = first.Ancestor(NodeKind.Block);
        var secondBlock = second.Ancestor(NodeKind.Block);
        if (firstBlock == null || firstBlock != secondBlock)
            return false;
        return first.Ancestor(NodeKind.If, NodeKind.Else, NodeKind.Loop, NodeKind.Match,
                   NodeKind.Try, NodeKind.Catch, NodeKind.Lambda)
               == second.Ancestor(NodeKind.If, NodeKind.Else, NodeKind.Loop, NodeKind.Match,
                   NodeKind.Try, NodeKind.Catch, NodeKind.Lambda);
    }
}

public sealed class DeadStoreRuleCs : DeadStoreRule
{
    public override string Key => "QG-CS-BUG-0149";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class DeadStoreRuleJava : DeadStoreRule
{
    public override string Key => "QG-JV-BUG-0203";
    public override string[] Languages => ["java"];
}

public sealed class DeadStoreRuleJs : DeadStoreRule
{
    public override string Key => "QG-JS-BUG-0147";
    public override string[] Languages => ["js", "ts"];
}

public sealed class DeadStoreRulePython : DeadStoreRule
{
    public override string Key => "QG-PY-BUG-0153";
    public override string[] Languages => ["py"];
}

public sealed class DeadStoreRulePhp : DeadStoreRule
{
    public override string Key => "QG-PP-BUG-0050";
    public override string[] Languages => ["php"];
}

public sealed class DeadStoreRuleGo : DeadStoreRule
{
    public override string Key => "QG-GO-BUG-0006";
    public override string[] Languages => ["go"];
}

public sealed class DeadStoreRuleRuby : DeadStoreRule
{
    public override string Key => "QG-RB-BUG-0031";
    public override string[] Languages => ["rb"];
}

public sealed class DeadStoreRuleSwift : DeadStoreRule
{
    public override string Key => "QG-SW-BUG-0035";
    public override string[] Languages => ["swift"];
}

public sealed class DeadStoreRuleCss : DeadStoreRule
{
    public override string Key => "QG-CSS-BUG-0060";
    public override string[] Languages => ["css"];
}

public sealed class DeadStoreRuleHtml : DeadStoreRule
{
    public override string Key => "QG-HTML-BUG-0060";
    public override string[] Languages => ["html"];
}

public sealed class DeadStoreRuleXml : DeadStoreRule
{
    public override string Key => "QG-XML-BUG-0035";
    public override string[] Languages => ["xml"];
}

public sealed class DeadStoreRuleTerraform : DeadStoreRule
{
    public override string Key => "QG-TF-BUG-0030";
    public override string[] Languages => ["tf"];
}

public sealed class DeadStoreRuleDockerfile : DeadStoreRule
{
    public override string Key => "QG-DK-BUG-0037";
    public override string[] Languages => ["dk"];
}

public sealed class DeadStoreRuleKubernetes : DeadStoreRule
{
    public override string Key => "QG-K8-BUG-0030";
    public override string[] Languages => ["k8"];
}

public sealed class DeadStoreRuleCloudFormation : DeadStoreRule
{
    public override string Key => "QG-CF-BUG-0030";
    public override string[] Languages => ["cf"];
}

public sealed class DeadStoreRuleJson : DeadStoreRule
{
    public override string Key => "QG-JSON-BUG-0031";
    public override string[] Languages => ["json"];
}

public sealed class DeadStoreRuleKotlin : DeadStoreRule
{
    public override string Key => "QG-KT-BUG-0071";
    public override string[] Languages => ["kt"];
}

public sealed class DeadStoreRuleDart : DeadStoreRule
{
    public override string Key => "QG-DART-BUG-0045";
    public override string[] Languages => ["dart"];
}

public abstract class UnusedLocalVariableRule : StructuralRuleBase
{
    public override string Name => "Local variables should be used";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var symbol in context.Semantics.AllSymbols())
        {
            if (symbol.Scope.Kind is not (ScopeKind.Function or ScopeKind.Block) || symbol.IsParameter)
                continue;
            if (!symbol.IsExplicitlyDeclared || symbol.Name.Contains('.'))
                continue;
            if (symbol.Usages.Any(u => u.Kind == UsageKind.Reference))
                continue;
            var declaration = symbol.Usages.FirstOrDefault(u => u.Kind == UsageKind.Declaration);
            if (declaration == null || symbol.Name.StartsWith('_'))
                continue;
            // Go says what leaves the package with a capital letter. A constant declared at the top
            // of a library and named that way is read by whoever imports it, and this scan cannot
            // see them — every exported MIME type in a web framework was reported as unread.
            if (context.Language.LanguageKey is "go" && char.IsUpper(symbol.Name[0])
                && symbol.Scope.Kind != ScopeKind.Function)
                continue;
            context.Report(declaration.Identifier, $"'{symbol.Name}' is assigned but never read; "
                                                   + "remove it or use the value it holds.");
        }
    }
}

public sealed class UnusedLocalVariableRuleCs : UnusedLocalVariableRule
{
    public override string Key => "QG-CS-SML-0499";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class UnusedLocalVariableRuleJava : UnusedLocalVariableRule
{
    public override string Key => "QG-JV-SML-0460";
    public override string[] Languages => ["java"];
}

public sealed class UnusedLocalVariableRuleJs : UnusedLocalVariableRule
{
    public override string Key => "QG-JS-SML-0376";
    public override string[] Languages => ["js", "ts"];
}

public sealed class UnusedLocalVariableRulePython : UnusedLocalVariableRule
{
    public override string Key => "QG-PY-SML-0255";
    public override string[] Languages => ["py"];
}

public sealed class UnusedLocalVariableRulePhp : UnusedLocalVariableRule
{
    public override string Key => "QG-PP-SML-0120";
    public override string[] Languages => ["php"];
}

public sealed class UnusedLocalVariableRuleGo : UnusedLocalVariableRule
{
    public override string Key => "QG-GO-SML-0034";
    public override string[] Languages => ["go"];
}

public sealed class UnusedLocalVariableRuleRuby : UnusedLocalVariableRule
{
    public override string Key => "QG-RB-SML-0038";
    public override string[] Languages => ["rb"];
}

public sealed class UnusedLocalVariableRuleSwift : UnusedLocalVariableRule
{
    public override string Key => "QG-SW-SML-0022";
    public override string[] Languages => ["swift"];
}

public sealed class UnusedLocalVariableRuleCss : UnusedLocalVariableRule
{
    public override string Key => "QG-CSS-SML-0043";
    public override string[] Languages => ["css"];
}

public sealed class UnusedLocalVariableRuleHtml : UnusedLocalVariableRule
{
    public override string Key => "QG-HTML-SML-0115";
    public override string[] Languages => ["html"];
}

public sealed class UnusedLocalVariableRuleXml : UnusedLocalVariableRule
{
    public override string Key => "QG-XML-SML-0030";
    public override string[] Languages => ["xml"];
}

public sealed class UnusedLocalVariableRuleTerraform : UnusedLocalVariableRule
{
    public override string Key => "QG-TF-SML-0022";
    public override string[] Languages => ["tf"];
}

public sealed class UnusedLocalVariableRuleDockerfile : UnusedLocalVariableRule
{
    public override string Key => "QG-DK-SML-0036";
    public override string[] Languages => ["dk"];
}

public sealed class UnusedLocalVariableRuleKubernetes : UnusedLocalVariableRule
{
    public override string Key => "QG-K8-SML-0030";
    public override string[] Languages => ["k8"];
}

public sealed class UnusedLocalVariableRuleCloudFormation : UnusedLocalVariableRule
{
    public override string Key => "QG-CF-SML-0023";
    public override string[] Languages => ["cf"];
}

public sealed class UnusedLocalVariableRuleJson : UnusedLocalVariableRule
{
    public override string Key => "QG-JSON-SML-0018";
    public override string[] Languages => ["json"];
}

public sealed class UnusedLocalVariableRuleKotlin : UnusedLocalVariableRule
{
    public override string Key => "QG-KT-SML-0131";
    public override string[] Languages => ["kt"];
}

public sealed class UnusedLocalVariableRuleDart : UnusedLocalVariableRule
{
    public override string Key => "QG-DART-SML-0049";
    public override string[] Languages => ["dart"];
}

public abstract class EmptyFunctionRule : StructuralRuleBase
{
    public override string Name => "Function bodies should not be empty";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        foreach (var function in SyntaxQuery.Functions(context.Root))
        {
            if (function.Kind == NodeKind.ConstructorDeclaration)
                continue; // an empty constructor is how a class says it takes no setup
            // A signature declared for the type checker alone carries no body by design: that is
            // what '@overload' and '@abstractmethod' mean, and asking them to be implemented asks
            // for the opposite of what they say.
            if (function.ChildrenOf(NodeKind.Attribute).Any(a =>
                    a.Text.Contains("overload", StringComparison.OrdinalIgnoreCase)
                    || a.Text.Contains("abstract", StringComparison.OrdinalIgnoreCase)))
                continue;
            var body = SyntaxQuery.Body(function);
            if (body is not { Children.Count: 0 })
                continue;
            // the rule asks for the emptiness to be documented, so a comment inside the body is the
            // answer to it — and the tree does not keep comments, which is why the tokens are read
            // strictly inside: a comment on the closing line is a note about the method, not in it
            if (context.Tokens.Any(t => t.Kind == Tokenization.TokenKind.Comment
                                        && t.Line > body.Range.StartLine && t.Line < body.Range.EndLine))
                continue;

            context.Report(function, $"'{function.Text}' has an empty body; implement it, "
                                     + "or document why doing nothing is the intended behaviour.");
        }
    }
}

public sealed class EmptyFunctionRuleCs : EmptyFunctionRule
{
    public override string Key => "QG-CS-SML-0501";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class EmptyFunctionRuleJava : EmptyFunctionRule
{
    public override string Key => "QG-JV-SML-0462";
    public override string[] Languages => ["java"];
}

public sealed class EmptyFunctionRuleJs : EmptyFunctionRule
{
    public override string Key => "QG-JS-SML-0378";
    public override string[] Languages => ["js", "ts"];
}

public sealed class EmptyFunctionRulePython : EmptyFunctionRule
{
    public override string Key => "QG-PY-SML-0257";
    public override string[] Languages => ["py"];
}

public sealed class EmptyFunctionRulePhp : EmptyFunctionRule
{
    public override string Key => "QG-PP-SML-0122";
    public override string[] Languages => ["php"];
}

public sealed class EmptyFunctionRuleGo : EmptyFunctionRule
{
    public override string Key => "QG-GO-SML-0036";
    public override string[] Languages => ["go"];
}

public sealed class EmptyFunctionRuleRuby : EmptyFunctionRule
{
    public override string Key => "QG-RB-SML-0039";
    public override string[] Languages => ["rb"];
}

public sealed class EmptyFunctionRuleSwift : EmptyFunctionRule
{
    public override string Key => "QG-SW-SML-0023";
    public override string[] Languages => ["swift"];
}

public sealed class EmptyFunctionRuleCss : EmptyFunctionRule
{
    public override string Key => "QG-CSS-SML-0044";
    public override string[] Languages => ["css"];
}

public sealed class EmptyFunctionRuleHtml : EmptyFunctionRule
{
    public override string Key => "QG-HTML-SML-0116";
    public override string[] Languages => ["html"];
}

public sealed class EmptyFunctionRuleXml : EmptyFunctionRule
{
    public override string Key => "QG-XML-SML-0031";
    public override string[] Languages => ["xml"];
}

public sealed class EmptyFunctionRuleTerraform : EmptyFunctionRule
{
    public override string Key => "QG-TF-SML-0023";
    public override string[] Languages => ["tf"];
}

public sealed class EmptyFunctionRuleDockerfile : EmptyFunctionRule
{
    public override string Key => "QG-DK-SML-0037";
    public override string[] Languages => ["dk"];
}

public sealed class EmptyFunctionRuleKubernetes : EmptyFunctionRule
{
    public override string Key => "QG-K8-SML-0031";
    public override string[] Languages => ["k8"];
}

public sealed class EmptyFunctionRuleCloudFormation : EmptyFunctionRule
{
    public override string Key => "QG-CF-SML-0024";
    public override string[] Languages => ["cf"];
}

public sealed class EmptyFunctionRuleJson : EmptyFunctionRule
{
    public override string Key => "QG-JSON-SML-0019";
    public override string[] Languages => ["json"];
}

public sealed class EmptyFunctionRuleKotlin : EmptyFunctionRule
{
    public override string Key => "QG-KT-SML-0132";
    public override string[] Languages => ["kt"];
}

public sealed class EmptyFunctionRuleDart : EmptyFunctionRule
{
    public override string Key => "QG-DART-SML-0050";
    public override string[] Languages => ["dart"];
}

public abstract class MultipleStatementsPerLineRule : StructuralRuleBase
{
    public override string Name => "One statement per line";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        // a real separator must exist on the line: this keeps generated terminators out of the result
        var separators = context.Tokens
            .Where(t => t.Kind == Tokenization.TokenKind.Symbol && t.Text == ";")
            .Select(t => t.Line)
            .ToHashSet();

        foreach (var parent in context.Root.DescendantsAndSelf())
        {
            if (parent.Kind is not (NodeKind.Block or NodeKind.TopLevel))
                continue;
            var statements = parent.Children
                .Where(c => c.Kind is NodeKind.ExpressionStatement or NodeKind.VariableDeclaration or NodeKind.Jump)
                .ToList();
            for (var i = 1; i < statements.Count; i++)
            {
                var line = statements[i].Line;
                if (line == 0 || line != statements[i - 1].Line || !separators.Contains(line))
                    continue;
                context.Report(statements[i], "This line holds more than one statement; "
                                              + "put each statement on its own line.");
            }
        }
    }

}

public sealed class MultipleStatementsPerLineRuleCs : MultipleStatementsPerLineRule
{
    public override string Key => "QG-CS-CNV-0011";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class MultipleStatementsPerLineRuleJava : MultipleStatementsPerLineRule
{
    public override string Key => "QG-JV-CNV-0003";
    public override string[] Languages => ["java"];
}

public sealed class MultipleStatementsPerLineRuleJs : MultipleStatementsPerLineRule
{
    public override string Key => "QG-JS-CNV-0003";
    public override string[] Languages => ["js", "ts"];
}

public sealed class MultipleStatementsPerLineRulePython : MultipleStatementsPerLineRule
{
    public override string Key => "QG-PY-CNV-0010";
    public override string[] Languages => ["py"];
}

public sealed class MultipleStatementsPerLineRulePhp : MultipleStatementsPerLineRule
{
    public override string Key => "QG-PP-CNV-0001";
    public override string[] Languages => ["php"];
}

public sealed class MultipleStatementsPerLineRuleGo : MultipleStatementsPerLineRule
{
    public override string Key => "QG-GO-CNV-0002";
    public override string[] Languages => ["go"];
}

public sealed class MultipleStatementsPerLineRuleRuby : MultipleStatementsPerLineRule
{
    public override string Key => "QG-RB-CNV-0002";
    public override string[] Languages => ["rb"];
}

public sealed class MultipleStatementsPerLineRuleSwift : MultipleStatementsPerLineRule
{
    public override string Key => "QG-SW-CNV-0002";
    public override string[] Languages => ["swift"];
}

public sealed class MultipleStatementsPerLineRuleCss : MultipleStatementsPerLineRule
{
    public override string Key => "QG-CSS-CNV-0002";
    public override string[] Languages => ["css"];
}

public sealed class MultipleStatementsPerLineRuleHtml : MultipleStatementsPerLineRule
{
    public override string Key => "QG-HTML-CNV-0002";
    public override string[] Languages => ["html"];
}

public sealed class MultipleStatementsPerLineRuleXml : MultipleStatementsPerLineRule
{
    public override string Key => "QG-XML-CNV-0001";
    public override string[] Languages => ["xml"];
}

public sealed class MultipleStatementsPerLineRuleTerraform : MultipleStatementsPerLineRule
{
    public override string Key => "QG-TF-CNV-0001";
    public override string[] Languages => ["tf"];
}

public sealed class MultipleStatementsPerLineRuleDockerfile : MultipleStatementsPerLineRule
{
    public override string Key => "QG-DK-CNV-0003";
    public override string[] Languages => ["dk"];
}

public sealed class MultipleStatementsPerLineRuleKubernetes : MultipleStatementsPerLineRule
{
    public override string Key => "QG-K8-CNV-0002";
    public override string[] Languages => ["k8"];
}

public sealed class MultipleStatementsPerLineRuleCloudFormation : MultipleStatementsPerLineRule
{
    public override string Key => "QG-CF-CNV-0001";
    public override string[] Languages => ["cf"];
}

public sealed class MultipleStatementsPerLineRuleJson : MultipleStatementsPerLineRule
{
    public override string Key => "QG-JSON-CNV-0001";
    public override string[] Languages => ["json"];
}

public sealed class MultipleStatementsPerLineRuleKotlin : MultipleStatementsPerLineRule
{
    public override string Key => "QG-KT-CNV-0010";
    public override string[] Languages => ["kt"];
}

public sealed class MultipleStatementsPerLineRuleDart : MultipleStatementsPerLineRule
{
    public override string Key => "QG-DART-CNV-0006";
    public override string[] Languages => ["dart"];
}

public abstract class StringConcatenationInLoopRule : StructuralRuleBase
{
    public override string Name => "Strings should not be built by concatenation inside a loop";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "15min";

    public override void Execute(IRuleContext context)
    {
        foreach (var loop in context.Root.OfKind(NodeKind.Loop))
        {
            foreach (var assignment in loop.OfKind(NodeKind.Assignment))
            {
                var target = assignment.ChildAt(0);
                var isStringTarget = target?.Symbol?.DeclaredType is "string" or "String" or "str"
                                     || SyntaxQuery.ConstantString(assignment.ChildAt(1)) != null;
                var concatenates = assignment.Text == "+=" && isStringTarget
                                   || assignment.Text == "=" && assignment.ChildAt(1) is { Kind: NodeKind.Binary, Text: "+" } value
                                   && SyntaxQuery.MentionsIdentifier(value, SyntaxQuery.DottedName(target));
                if (!concatenates)
                    continue;
                context.Report(assignment, "Each concatenation allocates a new string; accumulate the parts in "
                                           + "a string builder or a list and join them once after the loop.");
            }
        }
    }
}

public sealed class StringConcatenationInLoopRuleCs : StringConcatenationInLoopRule
{
    public override string Key => "QG-CS-PRF-0008";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class StringConcatenationInLoopRuleJava : StringConcatenationInLoopRule
{
    public override string Key => "QG-JV-PRF-0002";
    public override string[] Languages => ["java"];
}

public sealed class StringConcatenationInLoopRuleKotlin : StringConcatenationInLoopRule
{
    public override string Key => "QG-KT-PRF-0002";
    public override string[] Languages => ["kt"];
}

public sealed class StringConcatenationInLoopRuleJs : StringConcatenationInLoopRule
{
    public override string Key => "QG-JS-PRF-0001";
    public override string[] Languages => ["js", "ts"];
}

public sealed class StringConcatenationInLoopRulePython : StringConcatenationInLoopRule
{
    public override string Key => "QG-PY-PRF-0002";
    public override string[] Languages => ["py"];
}

public sealed class StringConcatenationInLoopRulePhp : StringConcatenationInLoopRule
{
    public override string Key => "QG-PP-PRF-0001";
    public override string[] Languages => ["php"];
}

public sealed class StringConcatenationInLoopRuleGo : StringConcatenationInLoopRule
{
    public override string Key => "QG-GO-PRF-0001";
    public override string[] Languages => ["go"];
}

public sealed class StringConcatenationInLoopRuleDart : StringConcatenationInLoopRule
{
    public override string Key => "QG-DART-PRF-0001";
    public override string[] Languages => ["dart"];
}

public sealed class StringConcatenationInLoopRuleRuby : StringConcatenationInLoopRule
{
    public override string Key => "QG-RB-PRF-0001";
    public override string[] Languages => ["rb"];
}

public sealed class StringConcatenationInLoopRuleSwift : StringConcatenationInLoopRule
{
    public override string Key => "QG-SW-PRF-0001";
    public override string[] Languages => ["swift"];
}

public sealed class StringConcatenationInLoopRuleCss : StringConcatenationInLoopRule
{
    public override string Key => "QG-CSS-PRF-0002";
    public override string[] Languages => ["css"];
}

public sealed class StringConcatenationInLoopRuleHtml : StringConcatenationInLoopRule
{
    public override string Key => "QG-HTML-PRF-0001";
    public override string[] Languages => ["html"];
}

public sealed class StringConcatenationInLoopRuleXml : StringConcatenationInLoopRule
{
    public override string Key => "QG-XML-PRF-0001";
    public override string[] Languages => ["xml"];
}

public sealed class StringConcatenationInLoopRuleTerraform : StringConcatenationInLoopRule
{
    public override string Key => "QG-TF-PRF-0001";
    public override string[] Languages => ["tf"];
}

public sealed class StringConcatenationInLoopRuleDockerfile : StringConcatenationInLoopRule
{
    public override string Key => "QG-DK-PRF-0001";
    public override string[] Languages => ["dk"];
}

public sealed class StringConcatenationInLoopRuleKubernetes : StringConcatenationInLoopRule
{
    public override string Key => "QG-K8-PRF-0001";
    public override string[] Languages => ["k8"];
}

public sealed class StringConcatenationInLoopRuleCloudFormation : StringConcatenationInLoopRule
{
    public override string Key => "QG-CF-PRF-0001";
    public override string[] Languages => ["cf"];
}

public sealed class StringConcatenationInLoopRuleJson : StringConcatenationInLoopRule
{
    public override string Key => "QG-JSON-PRF-0001";
    public override string[] Languages => ["json"];
}

public abstract class InvalidRegexRule : StructuralRuleBase
{
    /// <summary>Calls whose first string argument is a pattern whatever the receiver is.</summary>
    private static readonly string[] RegexEntryPoints =
    [
        "MustCompile", "MustCompilePOSIX", "new_regex", "RegExp", "Regex", "compile", "findall",
        "fullmatch", "IsMatch", "Matches"
    ];

    /// <summary>
    /// The same names exist on strings and on collections, where the argument is plain text:
    /// "path".Replace("\\", "/") is not a broken pattern. They only count when the receiver says
    /// the call goes through a regular expression engine.
    /// </summary>
    private static readonly string[] AmbiguousEntryPoints =
        ["Match", "Replace", "Split", "match", "search", "test", "exec", "matches", "sub", "subn"];

    private static readonly string[] RegexReceivers =
        ["Regex", "RegExp", "re", "Pattern", "regexp", "System.Text.RegularExpressions.Regex"];
    public override string Name => "Regular expressions should be syntactically valid";
    public override Severity Severity => Severity.Blocker;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "15min";

    public override void Execute(IRuleContext context)
    {
        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            var name = SyntaxQuery.InvokedName(call);
            var known = RegexEntryPoints.Contains(name, StringComparer.Ordinal);
            if (!known && !(AmbiguousEntryPoints.Contains(name, StringComparer.Ordinal)
                            && RegexReceivers.Contains(SyntaxQuery.Receiver(call), StringComparer.Ordinal)))
                continue;

            foreach (var argument in SyntaxQuery.Arguments(call).Where(SyntaxQuery.IsStringLiteral))
            {
                var pattern = argument.Text;
                // a single character is a separator, never a pattern worth compiling
                if (pattern.Length <= 1 || !LooksLikePattern(pattern) || IsValid(pattern))
                    continue;
                context.Report(argument, "This pattern does not compile, so the call throws the first "
                                         + "time it runs; fix the escaping or the unbalanced group.");
                break;
            }
        }
    }

    private static bool LooksLikePattern(string text)
        => text.IndexOfAny(['(', '[', '\\', '{', '|', '+', '*', '?', '^', '$']) >= 0;

    private static bool IsValid(string pattern)
    {
        try
        {
            _ = System.Text.RegularExpressions.Regex.Match(string.Empty, pattern);
            return true;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }
}

public sealed class InvalidRegexRuleCs : InvalidRegexRule
{
    public override string Key => "QG-CS-BUG-0156";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class InvalidRegexRuleJava : InvalidRegexRule
{
    public override string Key => "QG-JV-BUG-0210";
    public override string[] Languages => ["java"];
}

public sealed class InvalidRegexRuleKotlin : InvalidRegexRule
{
    public override string Key => "QG-KT-BUG-0037";
    public override string[] Languages => ["kt"];
}

public sealed class InvalidRegexRuleJs : InvalidRegexRule
{
    public override string Key => "QG-JS-BUG-0154";
    public override string[] Languages => ["js", "ts"];
}

public sealed class InvalidRegexRulePython : InvalidRegexRule
{
    public override string Key => "QG-PY-BUG-0160";
    public override string[] Languages => ["py"];
}

public sealed class InvalidRegexRulePhp : InvalidRegexRule
{
    public override string Key => "QG-PP-BUG-0057";
    public override string[] Languages => ["php"];
}

public sealed class InvalidRegexRuleGo : InvalidRegexRule
{
    public override string Key => "QG-GO-BUG-0013";
    public override string[] Languages => ["go"];
}

public sealed class InvalidRegexRuleDart : InvalidRegexRule
{
    public override string Key => "QG-DART-BUG-0011";
    public override string[] Languages => ["dart"];
}

public sealed class InvalidRegexRuleRuby : InvalidRegexRule
{
    public override string Key => "QG-RB-BUG-0032";
    public override string[] Languages => ["rb"];
}

public sealed class InvalidRegexRuleSwift : InvalidRegexRule
{
    public override string Key => "QG-SW-BUG-0036";
    public override string[] Languages => ["swift"];
}

public sealed class InvalidRegexRuleCss : InvalidRegexRule
{
    public override string Key => "QG-CSS-BUG-0061";
    public override string[] Languages => ["css"];
}

public sealed class InvalidRegexRuleHtml : InvalidRegexRule
{
    public override string Key => "QG-HTML-BUG-0061";
    public override string[] Languages => ["html"];
}

public sealed class InvalidRegexRuleXml : InvalidRegexRule
{
    public override string Key => "QG-XML-BUG-0036";
    public override string[] Languages => ["xml"];
}

public sealed class InvalidRegexRuleTerraform : InvalidRegexRule
{
    public override string Key => "QG-TF-BUG-0031";
    public override string[] Languages => ["tf"];
}

public sealed class InvalidRegexRuleDockerfile : InvalidRegexRule
{
    public override string Key => "QG-DK-BUG-0038";
    public override string[] Languages => ["dk"];
}

public sealed class InvalidRegexRuleKubernetes : InvalidRegexRule
{
    public override string Key => "QG-K8-BUG-0031";
    public override string[] Languages => ["k8"];
}

public sealed class InvalidRegexRuleCloudFormation : InvalidRegexRule
{
    public override string Key => "QG-CF-BUG-0031";
    public override string[] Languages => ["cf"];
}

public sealed class InvalidRegexRuleJson : InvalidRegexRule
{
    public override string Key => "QG-JSON-BUG-0032";
    public override string[] Languages => ["json"];
}

public abstract class FileTooLongRule : StructuralRuleBase
{
    private const int MaxLines = 1000;
    public override string Name => "Files should not grow beyond a readable size";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "60min";

    public override void Execute(IRuleContext context)
    {
        var lines = (int)context.Metrics.GetValueOrDefault("lines");
        if (lines > MaxLines)
            context.Report($"This file holds {lines} lines (limit is {MaxLines}); split it along the "
                           + "responsibilities it has accumulated.", 1);
    }
}

public sealed class FileTooLongRuleCs : FileTooLongRule
{
    public override string Key => "QG-CS-SML-0509";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class FileTooLongRuleJava : FileTooLongRule
{
    public override string Key => "QG-JV-SML-0470";
    public override string[] Languages => ["java"];
}

public sealed class FileTooLongRuleKotlin : FileTooLongRule
{
    public override string Key => "QG-KT-SML-0092";
    public override string[] Languages => ["kt"];
}

public sealed class FileTooLongRuleJs : FileTooLongRule
{
    public override string Key => "QG-JS-SML-0386";
    public override string[] Languages => ["js", "ts"];
}

public sealed class FileTooLongRulePython : FileTooLongRule
{
    public override string Key => "QG-PY-SML-0265";
    public override string[] Languages => ["py"];
}

public sealed class FileTooLongRulePhp : FileTooLongRule
{
    public override string Key => "QG-PP-SML-0130";
    public override string[] Languages => ["php"];
}

public sealed class FileTooLongRuleGo : FileTooLongRule
{
    public override string Key => "QG-GO-SML-0044";
    public override string[] Languages => ["go"];
}

public sealed class FileTooLongRuleDart : FileTooLongRule
{
    public override string Key => "QG-DART-SML-0009";
    public override string[] Languages => ["dart"];
}

public sealed class FileTooLongRuleRuby : FileTooLongRule
{
    public override string Key => "QG-RB-SML-0040";
    public override string[] Languages => ["rb"];
}

public sealed class FileTooLongRuleSwift : FileTooLongRule
{
    public override string Key => "QG-SW-SML-0024";
    public override string[] Languages => ["swift"];
}

public sealed class FileTooLongRuleCss : FileTooLongRule
{
    public override string Key => "QG-CSS-SML-0045";
    public override string[] Languages => ["css"];
}

public sealed class FileTooLongRuleHtml : FileTooLongRule
{
    public override string Key => "QG-HTML-SML-0117";
    public override string[] Languages => ["html"];
}

public sealed class FileTooLongRuleXml : FileTooLongRule
{
    public override string Key => "QG-XML-SML-0032";
    public override string[] Languages => ["xml"];
}

public sealed class FileTooLongRuleTerraform : FileTooLongRule
{
    public override string Key => "QG-TF-SML-0024";
    public override string[] Languages => ["tf"];
}

public sealed class FileTooLongRuleDockerfile : FileTooLongRule
{
    public override string Key => "QG-DK-SML-0038";
    public override string[] Languages => ["dk"];
}

public sealed class FileTooLongRuleKubernetes : FileTooLongRule
{
    public override string Key => "QG-K8-SML-0032";
    public override string[] Languages => ["k8"];
}

public sealed class FileTooLongRuleCloudFormation : FileTooLongRule
{
    public override string Key => "QG-CF-SML-0025";
    public override string[] Languages => ["cf"];
}

public sealed class FileTooLongRuleJson : FileTooLongRule
{
    public override string Key => "QG-JSON-SML-0020";
    public override string[] Languages => ["json"];
}

public abstract class UnusedParameterRule : StructuralRuleBase
{
    public override string Name => "Function parameters should be used";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var symbol in context.Semantics.AllSymbols())
        {
            if (!symbol.IsParameter || symbol.Name.Length <= 1 || symbol.Name[0] == '_')
                continue;
            if (symbol.Usages.Any(u => u.Kind is UsageKind.Reference or UsageKind.Assignment))
                continue;
            // an initialising formal (this.x, super.x) is consumed by the constructor itself
            if (symbol.Name.StartsWith("this.", StringComparison.Ordinal)
                || symbol.Name.StartsWith("super.", StringComparison.Ordinal))
                continue;
            var declaration = symbol.Usages.First(u => u.Kind == UsageKind.Parameter);
            // an override cannot change the signature it implements, so an unused parameter there is
            // imposed by the base type and not a decision the author can revisit
            var owner = SyntaxQuery.EnclosingFunction(declaration.Identifier);
            if (owner != null
                && owner.ChildrenOf(NodeKind.Attribute).Concat(owner.ChildrenOf(NodeKind.Modifier))
                    .Any(m => m.Text is "override" or "Override"))
                continue;
            // A method with no body — abstract, native, an interface member — declares a contract:
            // its parameters cannot be used because there is nothing to use them in. A method with
            // an empty body is the same idea written as a default hook.
            if (owner != null && SyntaxQuery.Body(owner) is not { Children.Count: > 0 })
                continue;
            // A decorated or annotated function is called by something else, with a signature that
            // something else decides: a route handler, an event hook, a fixture. The parameter is
            // there because the caller passes it, and removing it breaks the call.
            if (owner != null && owner.ChildrenOf(NodeKind.Attribute).Any())
                continue;
            // The name of a test's fixture is its request for that fixture, whether or not the body
            // reads it, and a test file is where most of these live.
            if (Rules.Languages.LanguageRuleSupport.IsTestFile(context.File.Path, context.File.FileName))
                continue;
            // A special method implements a protocol the language calls: the signature is fixed.
            if (owner != null && owner.Text.StartsWith("__", StringComparison.Ordinal)
                && owner.Text.EndsWith("__", StringComparison.Ordinal))
                continue;
            // Names the platform imposes: the entry point of a serverless function receives both
            // whether or not it reads them.
            if (symbol.Name is "self" or "cls" or "event" or "context" or "args" or "kwargs")
                continue;
            // A body that only declares itself unfinished has nothing to use the parameter in.
            if (owner != null && SyntaxQuery.Body(owner) is { } shell
                && shell.OfKind(NodeKind.Jump).Any(j => j.Text is "raise" or "throw")
                && shell.Children.Count == 1)
                continue;
            // The name may be read from a docstring or a comment — an annotation written as a
            // string, an example in the documentation — and that is a use the tree cannot show.
            if (context.Tokens.Any(t => t.Kind is Tokenization.TokenKind.String
                                            or Tokenization.TokenKind.Comment
                                        && t.Text.Contains(symbol.Name, StringComparison.Ordinal)))
                continue;

            context.Report(declaration.Identifier, $"'{symbol.Name}' is never used in the body; "
                                                   + "remove it or use the value the caller passes.");
        }
    }
}

public sealed class UnusedParameterRuleCs : UnusedParameterRule
{
    public override string Key => "QG-CS-SML-0497";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class UnusedParameterRuleJava : UnusedParameterRule
{
    public override string Key => "QG-JV-SML-0458";
    public override string[] Languages => ["java"];
}

public sealed class UnusedParameterRuleJs : UnusedParameterRule
{
    public override string Key => "QG-JS-SML-0374";
    public override string[] Languages => ["js", "ts"];
}

public sealed class UnusedParameterRulePython : UnusedParameterRule
{
    public override string Key => "QG-PY-SML-0253";
    public override string[] Languages => ["py"];
}

public sealed class UnusedParameterRulePhp : UnusedParameterRule
{
    public override string Key => "QG-PP-SML-0118";
    public override string[] Languages => ["php"];
}

public sealed class UnusedParameterRuleGo : UnusedParameterRule
{
    public override string Key => "QG-GO-SML-0032";
    public override string[] Languages => ["go"];
}

public sealed class UnusedParameterRuleRuby : UnusedParameterRule
{
    public override string Key => "QG-RB-SML-0041";
    public override string[] Languages => ["rb"];
}

public sealed class UnusedParameterRuleSwift : UnusedParameterRule
{
    public override string Key => "QG-SW-SML-0025";
    public override string[] Languages => ["swift"];
}

public sealed class UnusedParameterRuleCss : UnusedParameterRule
{
    public override string Key => "QG-CSS-SML-0046";
    public override string[] Languages => ["css"];
}

public sealed class UnusedParameterRuleHtml : UnusedParameterRule
{
    public override string Key => "QG-HTML-SML-0118";
    public override string[] Languages => ["html"];
}

public sealed class UnusedParameterRuleXml : UnusedParameterRule
{
    public override string Key => "QG-XML-SML-0033";
    public override string[] Languages => ["xml"];
}

public sealed class UnusedParameterRuleTerraform : UnusedParameterRule
{
    public override string Key => "QG-TF-SML-0025";
    public override string[] Languages => ["tf"];
}

public sealed class UnusedParameterRuleDockerfile : UnusedParameterRule
{
    public override string Key => "QG-DK-SML-0039";
    public override string[] Languages => ["dk"];
}

public sealed class UnusedParameterRuleKubernetes : UnusedParameterRule
{
    public override string Key => "QG-K8-SML-0033";
    public override string[] Languages => ["k8"];
}

public sealed class UnusedParameterRuleCloudFormation : UnusedParameterRule
{
    public override string Key => "QG-CF-SML-0026";
    public override string[] Languages => ["cf"];
}

public sealed class UnusedParameterRuleJson : UnusedParameterRule
{
    public override string Key => "QG-JSON-SML-0021";
    public override string[] Languages => ["json"];
}

public sealed class UnusedParameterRuleKotlin : UnusedParameterRule
{
    public override string Key => "QG-KT-SML-0133";
    public override string[] Languages => ["kt"];
}

public sealed class UnusedParameterRuleDart : UnusedParameterRule
{
    public override string Key => "QG-DART-SML-0051";
    public override string[] Languages => ["dart"];
}

public abstract class MergeableIfRule : StructuralRuleBase
{
    public override string Name => "Nested conditions that can be merged should be merged";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var outer in context.Root.OfKind(NodeKind.If))
        {
            var body = outer.FirstChild(NodeKind.Block);
            if (body is not { Children.Count: 1 })
                continue;
            var inner = body.Children[0];
            if (inner.Kind != NodeKind.If || inner.Children.Any(c => c.Kind == NodeKind.Else))
                continue;
            if (outer.Children.Any(c => c.Kind == NodeKind.Else))
                continue;
            context.Report(inner, "This condition is the only statement of the outer one; combine the two "
                                  + "tests with a logical AND to remove a level of nesting.");
        }
    }
}

public sealed class MergeableIfRuleCs : MergeableIfRule
{
    public override string Key => "QG-CS-SML-0510";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class MergeableIfRuleJava : MergeableIfRule
{
    public override string Key => "QG-JV-SML-0471";
    public override string[] Languages => ["java"];
}

public sealed class MergeableIfRuleKotlin : MergeableIfRule
{
    public override string Key => "QG-KT-SML-0093";
    public override string[] Languages => ["kt"];
}

public sealed class MergeableIfRuleJs : MergeableIfRule
{
    public override string Key => "QG-JS-SML-0387";
    public override string[] Languages => ["js", "ts"];
}

public sealed class MergeableIfRulePython : MergeableIfRule
{
    public override string Key => "QG-PY-SML-0266";
    public override string[] Languages => ["py"];
}

public sealed class MergeableIfRulePhp : MergeableIfRule
{
    public override string Key => "QG-PP-SML-0131";
    public override string[] Languages => ["php"];
}

public sealed class MergeableIfRuleGo : MergeableIfRule
{
    public override string Key => "QG-GO-SML-0045";
    public override string[] Languages => ["go"];
}

public sealed class MergeableIfRuleDart : MergeableIfRule
{
    public override string Key => "QG-DART-SML-0010";
    public override string[] Languages => ["dart"];
}

public sealed class MergeableIfRuleRuby : MergeableIfRule
{
    public override string Key => "QG-RB-SML-0042";
    public override string[] Languages => ["rb"];
}

public sealed class MergeableIfRuleSwift : MergeableIfRule
{
    public override string Key => "QG-SW-SML-0026";
    public override string[] Languages => ["swift"];
}

public sealed class MergeableIfRuleCss : MergeableIfRule
{
    public override string Key => "QG-CSS-SML-0047";
    public override string[] Languages => ["css"];
}

public sealed class MergeableIfRuleHtml : MergeableIfRule
{
    public override string Key => "QG-HTML-SML-0119";
    public override string[] Languages => ["html"];
}

public sealed class MergeableIfRuleXml : MergeableIfRule
{
    public override string Key => "QG-XML-SML-0034";
    public override string[] Languages => ["xml"];
}

public sealed class MergeableIfRuleTerraform : MergeableIfRule
{
    public override string Key => "QG-TF-SML-0026";
    public override string[] Languages => ["tf"];
}

public sealed class MergeableIfRuleDockerfile : MergeableIfRule
{
    public override string Key => "QG-DK-SML-0040";
    public override string[] Languages => ["dk"];
}

public sealed class MergeableIfRuleKubernetes : MergeableIfRule
{
    public override string Key => "QG-K8-SML-0034";
    public override string[] Languages => ["k8"];
}

public sealed class MergeableIfRuleCloudFormation : MergeableIfRule
{
    public override string Key => "QG-CF-SML-0027";
    public override string[] Languages => ["cf"];
}

public sealed class MergeableIfRuleJson : MergeableIfRule
{
    public override string Key => "QG-JSON-SML-0022";
    public override string[] Languages => ["json"];
}

public abstract class RedundantNestedBlockRule : StructuralRuleBase
{
    public override string Name => "Blocks should not be nested without a reason";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var block in Blocks(context))
        {
            if (block.Parent?.Kind != NodeKind.Block || block.Children.Count == 0 || block.Text != "free")
                continue;
            context.Report(block, "This block is not attached to any statement, so it only adds "
                                  + "indentation; remove the braces or extract the code into a function.");
        }
    }
}

public sealed class RedundantNestedBlockRuleCs : RedundantNestedBlockRule
{
    public override string Key => "QG-CS-SML-0511";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class RedundantNestedBlockRuleJava : RedundantNestedBlockRule
{
    public override string Key => "QG-JV-SML-0472";
    public override string[] Languages => ["java"];
}

public sealed class RedundantNestedBlockRuleKotlin : RedundantNestedBlockRule
{
    public override string Key => "QG-KT-SML-0094";
    public override string[] Languages => ["kt"];
}

public sealed class RedundantNestedBlockRuleJs : RedundantNestedBlockRule
{
    public override string Key => "QG-JS-SML-0388";
    public override string[] Languages => ["js", "ts"];
}

public sealed class RedundantNestedBlockRulePython : RedundantNestedBlockRule
{
    public override string Key => "QG-PY-SML-0267";
    public override string[] Languages => ["py"];
}

public sealed class RedundantNestedBlockRulePhp : RedundantNestedBlockRule
{
    public override string Key => "QG-PP-SML-0132";
    public override string[] Languages => ["php"];
}

public sealed class RedundantNestedBlockRuleGo : RedundantNestedBlockRule
{
    public override string Key => "QG-GO-SML-0046";
    public override string[] Languages => ["go"];
}

public sealed class RedundantNestedBlockRuleDart : RedundantNestedBlockRule
{
    public override string Key => "QG-DART-SML-0011";
    public override string[] Languages => ["dart"];
}

public sealed class RedundantNestedBlockRuleRuby : RedundantNestedBlockRule
{
    public override string Key => "QG-RB-SML-0043";
    public override string[] Languages => ["rb"];
}

public sealed class RedundantNestedBlockRuleSwift : RedundantNestedBlockRule
{
    public override string Key => "QG-SW-SML-0027";
    public override string[] Languages => ["swift"];
}

public sealed class RedundantNestedBlockRuleCss : RedundantNestedBlockRule
{
    public override string Key => "QG-CSS-SML-0048";
    public override string[] Languages => ["css"];
}

public sealed class RedundantNestedBlockRuleHtml : RedundantNestedBlockRule
{
    public override string Key => "QG-HTML-SML-0120";
    public override string[] Languages => ["html"];
}

public sealed class RedundantNestedBlockRuleXml : RedundantNestedBlockRule
{
    public override string Key => "QG-XML-SML-0035";
    public override string[] Languages => ["xml"];
}

public sealed class RedundantNestedBlockRuleTerraform : RedundantNestedBlockRule
{
    public override string Key => "QG-TF-SML-0027";
    public override string[] Languages => ["tf"];
}

public sealed class RedundantNestedBlockRuleDockerfile : RedundantNestedBlockRule
{
    public override string Key => "QG-DK-SML-0041";
    public override string[] Languages => ["dk"];
}

public sealed class RedundantNestedBlockRuleKubernetes : RedundantNestedBlockRule
{
    public override string Key => "QG-K8-SML-0035";
    public override string[] Languages => ["k8"];
}

public sealed class RedundantNestedBlockRuleCloudFormation : RedundantNestedBlockRule
{
    public override string Key => "QG-CF-SML-0028";
    public override string[] Languages => ["cf"];
}

public sealed class RedundantNestedBlockRuleJson : RedundantNestedBlockRule
{
    public override string Key => "QG-JSON-SML-0023";
    public override string[] Languages => ["json"];
}

public abstract class IfChainWithoutElseRule : StructuralRuleBase
{
    public override string Name => "Condition chains should end with a final branch";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var head in context.Root.OfKind(NodeKind.If))
        {
            if (DuplicateConditionRule.IsElseIf(head))
                continue;
            var chain = DuplicateConditionRule.Chain(head).ToList();
            if (chain.Count < 2 || DuplicateConditionRule.FinalElse(chain[^1]) != null)
                continue;
            context.Report(chain[^1], "No branch covers the remaining cases; add a final else that "
                                      + "handles or rejects the values the chain does not list.");
        }
    }
}

public sealed class IfChainWithoutElseRuleCs : IfChainWithoutElseRule
{
    public override string Key => "QG-CS-SML-0512";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class IfChainWithoutElseRuleJava : IfChainWithoutElseRule
{
    public override string Key => "QG-JV-SML-0473";
    public override string[] Languages => ["java"];
}

public sealed class IfChainWithoutElseRuleKotlin : IfChainWithoutElseRule
{
    public override string Key => "QG-KT-SML-0095";
    public override string[] Languages => ["kt"];
}

public sealed class IfChainWithoutElseRuleJs : IfChainWithoutElseRule
{
    public override string Key => "QG-JS-SML-0389";
    public override string[] Languages => ["js", "ts"];
}

public sealed class IfChainWithoutElseRulePython : IfChainWithoutElseRule
{
    public override string Key => "QG-PY-SML-0268";
    public override string[] Languages => ["py"];
}

public sealed class IfChainWithoutElseRulePhp : IfChainWithoutElseRule
{
    public override string Key => "QG-PP-SML-0133";
    public override string[] Languages => ["php"];
}

public sealed class IfChainWithoutElseRuleGo : IfChainWithoutElseRule
{
    public override string Key => "QG-GO-SML-0047";
    public override string[] Languages => ["go"];
}

public sealed class IfChainWithoutElseRuleDart : IfChainWithoutElseRule
{
    public override string Key => "QG-DART-SML-0012";
    public override string[] Languages => ["dart"];
}

public sealed class IfChainWithoutElseRuleRuby : IfChainWithoutElseRule
{
    public override string Key => "QG-RB-SML-0044";
    public override string[] Languages => ["rb"];
}

public sealed class IfChainWithoutElseRuleSwift : IfChainWithoutElseRule
{
    public override string Key => "QG-SW-SML-0028";
    public override string[] Languages => ["swift"];
}

public sealed class IfChainWithoutElseRuleCss : IfChainWithoutElseRule
{
    public override string Key => "QG-CSS-SML-0049";
    public override string[] Languages => ["css"];
}

public sealed class IfChainWithoutElseRuleHtml : IfChainWithoutElseRule
{
    public override string Key => "QG-HTML-SML-0121";
    public override string[] Languages => ["html"];
}

public sealed class IfChainWithoutElseRuleXml : IfChainWithoutElseRule
{
    public override string Key => "QG-XML-SML-0036";
    public override string[] Languages => ["xml"];
}

public sealed class IfChainWithoutElseRuleTerraform : IfChainWithoutElseRule
{
    public override string Key => "QG-TF-SML-0028";
    public override string[] Languages => ["tf"];
}

public sealed class IfChainWithoutElseRuleDockerfile : IfChainWithoutElseRule
{
    public override string Key => "QG-DK-SML-0042";
    public override string[] Languages => ["dk"];
}

public sealed class IfChainWithoutElseRuleKubernetes : IfChainWithoutElseRule
{
    public override string Key => "QG-K8-SML-0036";
    public override string[] Languages => ["k8"];
}

public sealed class IfChainWithoutElseRuleCloudFormation : IfChainWithoutElseRule
{
    public override string Key => "QG-CF-SML-0029";
    public override string[] Languages => ["cf"];
}

public sealed class IfChainWithoutElseRuleJson : IfChainWithoutElseRule
{
    public override string Key => "QG-JSON-SML-0024";
    public override string[] Languages => ["json"];
}

public abstract class ComplexConditionRule : StructuralRuleBase
{
    private const int MaxOperators = 4;
    public override string Name => "Conditions should not combine too many operators";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "15min";

    public override void Execute(IRuleContext context)
    {
        foreach (var branch in context.Root.OfKind(NodeKind.If, NodeKind.Loop))
        {
            if (Condition(branch) is not { } condition)
                continue;
            var operators = condition.DescendantsAndSelf()
                .Count(n => n.Kind == NodeKind.Binary && n.Text is "&&" or "||" or "and" or "or");
            if (operators > MaxOperators)
                context.Report(condition, $"This condition combines {operators} logical operators "
                                          + $"(limit is {MaxOperators}); name the parts in well-named "
                                          + "variables or a predicate function.");
        }
    }
}

public sealed class ComplexConditionRuleCs : ComplexConditionRule
{
    public override string Key => "QG-CS-SML-0513";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class ComplexConditionRuleJava : ComplexConditionRule
{
    public override string Key => "QG-JV-SML-0474";
    public override string[] Languages => ["java"];
}

public sealed class ComplexConditionRuleKotlin : ComplexConditionRule
{
    public override string Key => "QG-KT-SML-0096";
    public override string[] Languages => ["kt"];
}

public sealed class ComplexConditionRuleJs : ComplexConditionRule
{
    public override string Key => "QG-JS-SML-0390";
    public override string[] Languages => ["js", "ts"];
}

public sealed class ComplexConditionRulePython : ComplexConditionRule
{
    public override string Key => "QG-PY-SML-0269";
    public override string[] Languages => ["py"];
}

public sealed class ComplexConditionRulePhp : ComplexConditionRule
{
    public override string Key => "QG-PP-SML-0134";
    public override string[] Languages => ["php"];
}

public sealed class ComplexConditionRuleGo : ComplexConditionRule
{
    public override string Key => "QG-GO-SML-0048";
    public override string[] Languages => ["go"];
}

public sealed class ComplexConditionRuleDart : ComplexConditionRule
{
    public override string Key => "QG-DART-SML-0013";
    public override string[] Languages => ["dart"];
}

public sealed class ComplexConditionRuleRuby : ComplexConditionRule
{
    public override string Key => "QG-RB-SML-0045";
    public override string[] Languages => ["rb"];
}

public sealed class ComplexConditionRuleSwift : ComplexConditionRule
{
    public override string Key => "QG-SW-SML-0029";
    public override string[] Languages => ["swift"];
}

public sealed class ComplexConditionRuleCss : ComplexConditionRule
{
    public override string Key => "QG-CSS-SML-0050";
    public override string[] Languages => ["css"];
}

public sealed class ComplexConditionRuleHtml : ComplexConditionRule
{
    public override string Key => "QG-HTML-SML-0122";
    public override string[] Languages => ["html"];
}

public sealed class ComplexConditionRuleXml : ComplexConditionRule
{
    public override string Key => "QG-XML-SML-0037";
    public override string[] Languages => ["xml"];
}

public sealed class ComplexConditionRuleTerraform : ComplexConditionRule
{
    public override string Key => "QG-TF-SML-0029";
    public override string[] Languages => ["tf"];
}

public sealed class ComplexConditionRuleDockerfile : ComplexConditionRule
{
    public override string Key => "QG-DK-SML-0043";
    public override string[] Languages => ["dk"];
}

public sealed class ComplexConditionRuleKubernetes : ComplexConditionRule
{
    public override string Key => "QG-K8-SML-0037";
    public override string[] Languages => ["k8"];
}

public sealed class ComplexConditionRuleCloudFormation : ComplexConditionRule
{
    public override string Key => "QG-CF-SML-0030";
    public override string[] Languages => ["cf"];
}

public sealed class ComplexConditionRuleJson : ComplexConditionRule
{
    public override string Key => "QG-JSON-SML-0025";
    public override string[] Languages => ["json"];
}

public abstract class NestedMatchRule : StructuralRuleBase
{
    public override string Name => "Multi-way branches should not be nested";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "25min";

    public override void Execute(IRuleContext context)
    {
        foreach (var match in context.Root.OfKind(NodeKind.Match))
        {
            if (match.Ancestor(NodeKind.Match) == null)
                continue;
            context.Report(match, "A switch inside another switch multiplies the cases a reader has to "
                                  + "track; move the inner one into a function named after its decision.");
        }
    }
}

public sealed class NestedMatchRuleCs : NestedMatchRule
{
    public override string Key => "QG-CS-SML-0514";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class NestedMatchRuleJava : NestedMatchRule
{
    public override string Key => "QG-JV-SML-0475";
    public override string[] Languages => ["java"];
}

public sealed class NestedMatchRuleKotlin : NestedMatchRule
{
    public override string Key => "QG-KT-SML-0097";
    public override string[] Languages => ["kt"];
}

public sealed class NestedMatchRuleJs : NestedMatchRule
{
    public override string Key => "QG-JS-SML-0391";
    public override string[] Languages => ["js", "ts"];
}

public sealed class NestedMatchRulePython : NestedMatchRule
{
    public override string Key => "QG-PY-SML-0270";
    public override string[] Languages => ["py"];
}

public sealed class NestedMatchRulePhp : NestedMatchRule
{
    public override string Key => "QG-PP-SML-0135";
    public override string[] Languages => ["php"];
}

public sealed class NestedMatchRuleGo : NestedMatchRule
{
    public override string Key => "QG-GO-SML-0049";
    public override string[] Languages => ["go"];
}

public sealed class NestedMatchRuleDart : NestedMatchRule
{
    public override string Key => "QG-DART-SML-0014";
    public override string[] Languages => ["dart"];
}

public sealed class NestedMatchRuleRuby : NestedMatchRule
{
    public override string Key => "QG-RB-SML-0046";
    public override string[] Languages => ["rb"];
}

public sealed class NestedMatchRuleSwift : NestedMatchRule
{
    public override string Key => "QG-SW-SML-0030";
    public override string[] Languages => ["swift"];
}

public sealed class NestedMatchRuleCss : NestedMatchRule
{
    public override string Key => "QG-CSS-SML-0051";
    public override string[] Languages => ["css"];
}

public sealed class NestedMatchRuleHtml : NestedMatchRule
{
    public override string Key => "QG-HTML-SML-0123";
    public override string[] Languages => ["html"];
}

public sealed class NestedMatchRuleXml : NestedMatchRule
{
    public override string Key => "QG-XML-SML-0038";
    public override string[] Languages => ["xml"];
}

public sealed class NestedMatchRuleTerraform : NestedMatchRule
{
    public override string Key => "QG-TF-SML-0030";
    public override string[] Languages => ["tf"];
}

public sealed class NestedMatchRuleDockerfile : NestedMatchRule
{
    public override string Key => "QG-DK-SML-0044";
    public override string[] Languages => ["dk"];
}

public sealed class NestedMatchRuleKubernetes : NestedMatchRule
{
    public override string Key => "QG-K8-SML-0038";
    public override string[] Languages => ["k8"];
}

public sealed class NestedMatchRuleCloudFormation : NestedMatchRule
{
    public override string Key => "QG-CF-SML-0031";
    public override string[] Languages => ["cf"];
}

public sealed class NestedMatchRuleJson : NestedMatchRule
{
    public override string Key => "QG-JSON-SML-0026";
    public override string[] Languages => ["json"];
}

public abstract class MissingBracesRule : StructuralRuleBase
{
    public override string Name => "Control structures should always use a block";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        if (context.Tree.Profile.Style != StructureStyle.Braces)
            return;

        foreach (var branch in context.Root.OfKind(NodeKind.If, NodeKind.Loop, NodeKind.Else))
        {
            if (branch.FirstChild(NodeKind.Block) != null || branch.Children.Count == 0)
                continue;
            if (branch.Children.All(c => c.Kind is not (NodeKind.ExpressionStatement or NodeKind.Jump
                    or NodeKind.VariableDeclaration)))
                continue;
            context.Report(branch, "The body of this statement is not wrapped in braces; adding a second "
                                   + "line later then silently leaves it outside the branch.");
        }
    }
}

public sealed class MissingBracesRuleCs : MissingBracesRule
{
    public override string Key => "QG-CS-CNV-0015";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class MissingBracesRuleJava : MissingBracesRule
{
    public override string Key => "QG-JV-CNV-0007";
    public override string[] Languages => ["java"];
}

public sealed class MissingBracesRuleKotlin : MissingBracesRule
{
    public override string Key => "QG-KT-CNV-0009";
    public override string[] Languages => ["kt"];
}

public sealed class MissingBracesRuleJs : MissingBracesRule
{
    public override string Key => "QG-JS-CNV-0007";
    public override string[] Languages => ["js", "ts"];
}

public sealed class MissingBracesRulePython : MissingBracesRule
{
    public override string Key => "QG-PY-CNV-0014";
    public override string[] Languages => ["py"];
}

public sealed class MissingBracesRulePhp : MissingBracesRule
{
    public override string Key => "QG-PP-CNV-0005";
    public override string[] Languages => ["php"];
}

public sealed class MissingBracesRuleGo : MissingBracesRule
{
    public override string Key => "QG-GO-CNV-0006";
    public override string[] Languages => ["go"];
}

public sealed class MissingBracesRuleDart : MissingBracesRule
{
    public override string Key => "QG-DART-CNV-0005";
    public override string[] Languages => ["dart"];
}

public sealed class MissingBracesRuleRuby : MissingBracesRule
{
    public override string Key => "QG-RB-CNV-0003";
    public override string[] Languages => ["rb"];
}

public sealed class MissingBracesRuleSwift : MissingBracesRule
{
    public override string Key => "QG-SW-CNV-0003";
    public override string[] Languages => ["swift"];
}

public sealed class MissingBracesRuleCss : MissingBracesRule
{
    public override string Key => "QG-CSS-CNV-0003";
    public override string[] Languages => ["css"];
}

public sealed class MissingBracesRuleHtml : MissingBracesRule
{
    public override string Key => "QG-HTML-CNV-0003";
    public override string[] Languages => ["html"];
}

public sealed class MissingBracesRuleXml : MissingBracesRule
{
    public override string Key => "QG-XML-CNV-0002";
    public override string[] Languages => ["xml"];
}

public sealed class MissingBracesRuleTerraform : MissingBracesRule
{
    public override string Key => "QG-TF-CNV-0002";
    public override string[] Languages => ["tf"];
}

public sealed class MissingBracesRuleDockerfile : MissingBracesRule
{
    public override string Key => "QG-DK-CNV-0004";
    public override string[] Languages => ["dk"];
}

public sealed class MissingBracesRuleKubernetes : MissingBracesRule
{
    public override string Key => "QG-K8-CNV-0003";
    public override string[] Languages => ["k8"];
}

public sealed class MissingBracesRuleCloudFormation : MissingBracesRule
{
    public override string Key => "QG-CF-CNV-0002";
    public override string[] Languages => ["cf"];
}

public sealed class MissingBracesRuleJson : MissingBracesRule
{
    public override string Key => "QG-JSON-CNV-0002";
    public override string[] Languages => ["json"];
}


public abstract class TooManyReturnsRule : StructuralRuleBase
{
    private const int Max = 6;
    public override string Name => "Functions should not have too many exit points";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "20min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var function in SyntaxQuery.Functions(context.Root))
        {
            var returns = function.OfKind(NodeKind.Jump)
                .Count(j => j.Text.StartsWith("return", StringComparison.Ordinal)
                            && SyntaxQuery.EnclosingFunction(j) == function);
            if (returns > Max)
                context.Report(function, $"'{function.Text}' returns from {returns} places (limit is {Max}); "
                                         + "compute one result and return it once.");
        }
    }
}

public sealed class TooManyReturnsRuleCs : TooManyReturnsRule
{
    public override string Key => "QG-CS-SML-0515";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class TooManyReturnsRuleJava : TooManyReturnsRule
{
    public override string Key => "QG-JV-SML-0476";
    public override string[] Languages => ["java"];
}

public sealed class TooManyReturnsRuleKotlin : TooManyReturnsRule
{
    public override string Key => "QG-KT-SML-0098";
    public override string[] Languages => ["kt"];
}

public sealed class TooManyReturnsRuleJs : TooManyReturnsRule
{
    public override string Key => "QG-JS-SML-0392";
    public override string[] Languages => ["js", "ts"];
}

public sealed class TooManyReturnsRulePython : TooManyReturnsRule
{
    public override string Key => "QG-PY-SML-0271";
    public override string[] Languages => ["py"];
}

public sealed class TooManyReturnsRulePhp : TooManyReturnsRule
{
    public override string Key => "QG-PP-SML-0136";
    public override string[] Languages => ["php"];
}

public sealed class TooManyReturnsRuleGo : TooManyReturnsRule
{
    public override string Key => "QG-GO-SML-0050";
    public override string[] Languages => ["go"];
}

public sealed class TooManyReturnsRuleDart : TooManyReturnsRule
{
    public override string Key => "QG-DART-SML-0015";
    public override string[] Languages => ["dart"];
}

public sealed class TooManyReturnsRuleRuby : TooManyReturnsRule
{
    public override string Key => "QG-RB-SML-0047";
    public override string[] Languages => ["rb"];
}

public sealed class TooManyReturnsRuleSwift : TooManyReturnsRule
{
    public override string Key => "QG-SW-SML-0031";
    public override string[] Languages => ["swift"];
}

public sealed class TooManyReturnsRuleCss : TooManyReturnsRule
{
    public override string Key => "QG-CSS-SML-0052";
    public override string[] Languages => ["css"];
}

public sealed class TooManyReturnsRuleHtml : TooManyReturnsRule
{
    public override string Key => "QG-HTML-SML-0124";
    public override string[] Languages => ["html"];
}

public sealed class TooManyReturnsRuleXml : TooManyReturnsRule
{
    public override string Key => "QG-XML-SML-0039";
    public override string[] Languages => ["xml"];
}

public sealed class TooManyReturnsRuleTerraform : TooManyReturnsRule
{
    public override string Key => "QG-TF-SML-0031";
    public override string[] Languages => ["tf"];
}

public sealed class TooManyReturnsRuleDockerfile : TooManyReturnsRule
{
    public override string Key => "QG-DK-SML-0045";
    public override string[] Languages => ["dk"];
}

public sealed class TooManyReturnsRuleKubernetes : TooManyReturnsRule
{
    public override string Key => "QG-K8-SML-0039";
    public override string[] Languages => ["k8"];
}

public sealed class TooManyReturnsRuleCloudFormation : TooManyReturnsRule
{
    public override string Key => "QG-CF-SML-0032";
    public override string[] Languages => ["cf"];
}

public sealed class TooManyReturnsRuleJson : TooManyReturnsRule
{
    public override string Key => "QG-JSON-SML-0027";
    public override string[] Languages => ["json"];
}

public abstract class EmptyCatchRule : StructuralRuleBase
{
    public override string Name => "Caught exceptions should not be ignored";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var handler in context.Root.OfKind(NodeKind.Catch))
        {
            var body = handler.FirstChild(NodeKind.Block);
            if (body is not { Children.Count: 0 })
                continue;
            // a comment inside the block is an explicit decision, and the tokenizer keeps it
            var hasComment = context.Tokens.Any(t => t.Kind == Tokenization.TokenKind.Comment
                                                     && t.Line >= handler.Line && t.Line <= handler.EndLine);
            if (hasComment)
                continue;
            context.Report(handler, "This handler discards the failure without recording it; "
                                    + "log it with context or let it propagate.");
        }
    }
}

public sealed class EmptyCatchRuleCs : EmptyCatchRule
{
    public override string Key => "QG-CS-SML-0516";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class EmptyCatchRuleJava : EmptyCatchRule
{
    public override string Key => "QG-JV-SML-0477";
    public override string[] Languages => ["java"];
}

public sealed class EmptyCatchRuleKotlin : EmptyCatchRule
{
    public override string Key => "QG-KT-SML-0099";
    public override string[] Languages => ["kt"];
}

public sealed class EmptyCatchRuleJs : EmptyCatchRule
{
    public override string Key => "QG-JS-SML-0393";
    public override string[] Languages => ["js", "ts"];
}

public sealed class EmptyCatchRulePython : EmptyCatchRule
{
    public override string Key => "QG-PY-SML-0272";
    public override string[] Languages => ["py"];
}

public sealed class EmptyCatchRulePhp : EmptyCatchRule
{
    public override string Key => "QG-PP-SML-0137";
    public override string[] Languages => ["php"];
}

public sealed class EmptyCatchRuleGo : EmptyCatchRule
{
    public override string Key => "QG-GO-SML-0051";
    public override string[] Languages => ["go"];
}

public sealed class EmptyCatchRuleDart : EmptyCatchRule
{
    public override string Key => "QG-DART-SML-0016";
    public override string[] Languages => ["dart"];
}

public sealed class EmptyCatchRuleRuby : EmptyCatchRule
{
    public override string Key => "QG-RB-SML-0048";
    public override string[] Languages => ["rb"];
}

public sealed class EmptyCatchRuleSwift : EmptyCatchRule
{
    public override string Key => "QG-SW-SML-0032";
    public override string[] Languages => ["swift"];
}

public sealed class EmptyCatchRuleCss : EmptyCatchRule
{
    public override string Key => "QG-CSS-SML-0053";
    public override string[] Languages => ["css"];
}

public sealed class EmptyCatchRuleHtml : EmptyCatchRule
{
    public override string Key => "QG-HTML-SML-0125";
    public override string[] Languages => ["html"];
}

public sealed class EmptyCatchRuleXml : EmptyCatchRule
{
    public override string Key => "QG-XML-SML-0040";
    public override string[] Languages => ["xml"];
}

public sealed class EmptyCatchRuleTerraform : EmptyCatchRule
{
    public override string Key => "QG-TF-SML-0032";
    public override string[] Languages => ["tf"];
}

public sealed class EmptyCatchRuleDockerfile : EmptyCatchRule
{
    public override string Key => "QG-DK-SML-0046";
    public override string[] Languages => ["dk"];
}

public sealed class EmptyCatchRuleKubernetes : EmptyCatchRule
{
    public override string Key => "QG-K8-SML-0040";
    public override string[] Languages => ["k8"];
}

public sealed class EmptyCatchRuleCloudFormation : EmptyCatchRule
{
    public override string Key => "QG-CF-SML-0033";
    public override string[] Languages => ["cf"];
}

public sealed class EmptyCatchRuleJson : EmptyCatchRule
{
    public override string Key => "QG-JSON-SML-0028";
    public override string[] Languages => ["json"];
}

public abstract class BooleanLiteralComparisonRule : StructuralRuleBase
{
    public override string Name => "Boolean values should not be compared with literals";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var comparison in context.Root.OfKind(NodeKind.Binary))
        {
            if (comparison.Text is not ("==" or "!=" or "===" or "!=="))
                continue;
            if (!comparison.Children.Any(c => c.Kind == NodeKind.BooleanLiteral))
                continue;

            // A nullable boolean has three values, and 'x != true' is the only short way to say
            // "false or missing". Replacing it with '!x' changes the answer when x is null, so the
            // comparison is kept wherever the operand can be null.
            var other = comparison.Children.FirstOrDefault(c => c.Kind != NodeKind.BooleanLiteral);
            if (other != null && MayBeNull(context, other))
                continue;

            context.Report(comparison, "Comparing with a boolean literal restates the value; "
                                       + "use the expression itself, negated when needed.");
        }
    }

    /// <summary>
    /// Whether the compared value can be null, which makes the comparison say something the plain
    /// expression cannot. The declared type answers it when it is in reach; when it is not, the rule
    /// stays quiet rather than change what the code means.
    /// </summary>
    private static bool MayBeNull(IRuleContext context, SyntaxNode expression)
    {
        var type = context.Types.TypeOf(expression);
        if (type is { Length: > 0 })
            return type.EndsWith('?') || type.StartsWith("Nullable", StringComparison.Ordinal);
        return true;
    }
}

public sealed class BooleanLiteralComparisonRuleCs : BooleanLiteralComparisonRule
{
    public override string Key => "QG-CS-SML-0517";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class BooleanLiteralComparisonRuleJava : BooleanLiteralComparisonRule
{
    public override string Key => "QG-JV-SML-0478";
    public override string[] Languages => ["java"];
}

public sealed class BooleanLiteralComparisonRuleKotlin : BooleanLiteralComparisonRule
{
    public override string Key => "QG-KT-SML-0100";
    public override string[] Languages => ["kt"];
}

public sealed class BooleanLiteralComparisonRuleJs : BooleanLiteralComparisonRule
{
    public override string Key => "QG-JS-SML-0394";
    public override string[] Languages => ["js", "ts"];
}

public sealed class BooleanLiteralComparisonRulePython : BooleanLiteralComparisonRule
{
    public override string Key => "QG-PY-SML-0273";
    public override string[] Languages => ["py"];
}

public sealed class BooleanLiteralComparisonRulePhp : BooleanLiteralComparisonRule
{
    public override string Key => "QG-PP-SML-0138";
    public override string[] Languages => ["php"];
}

public sealed class BooleanLiteralComparisonRuleGo : BooleanLiteralComparisonRule
{
    public override string Key => "QG-GO-SML-0052";
    public override string[] Languages => ["go"];
}

public sealed class BooleanLiteralComparisonRuleDart : BooleanLiteralComparisonRule
{
    public override string Key => "QG-DART-SML-0017";
    public override string[] Languages => ["dart"];
}

public sealed class BooleanLiteralComparisonRuleRuby : BooleanLiteralComparisonRule
{
    public override string Key => "QG-RB-SML-0049";
    public override string[] Languages => ["rb"];
}

public sealed class BooleanLiteralComparisonRuleSwift : BooleanLiteralComparisonRule
{
    public override string Key => "QG-SW-SML-0033";
    public override string[] Languages => ["swift"];
}

public sealed class BooleanLiteralComparisonRuleCss : BooleanLiteralComparisonRule
{
    public override string Key => "QG-CSS-SML-0054";
    public override string[] Languages => ["css"];
}

public sealed class BooleanLiteralComparisonRuleHtml : BooleanLiteralComparisonRule
{
    public override string Key => "QG-HTML-SML-0126";
    public override string[] Languages => ["html"];
}

public sealed class BooleanLiteralComparisonRuleXml : BooleanLiteralComparisonRule
{
    public override string Key => "QG-XML-SML-0041";
    public override string[] Languages => ["xml"];
}

public sealed class BooleanLiteralComparisonRuleTerraform : BooleanLiteralComparisonRule
{
    public override string Key => "QG-TF-SML-0033";
    public override string[] Languages => ["tf"];
}

public sealed class BooleanLiteralComparisonRuleDockerfile : BooleanLiteralComparisonRule
{
    public override string Key => "QG-DK-SML-0047";
    public override string[] Languages => ["dk"];
}

public sealed class BooleanLiteralComparisonRuleKubernetes : BooleanLiteralComparisonRule
{
    public override string Key => "QG-K8-SML-0041";
    public override string[] Languages => ["k8"];
}

public sealed class BooleanLiteralComparisonRuleCloudFormation : BooleanLiteralComparisonRule
{
    public override string Key => "QG-CF-SML-0034";
    public override string[] Languages => ["cf"];
}

public sealed class BooleanLiteralComparisonRuleJson : BooleanLiteralComparisonRule
{
    public override string Key => "QG-JSON-SML-0029";
    public override string[] Languages => ["json"];
}

public abstract class MagicNumberRule : StructuralRuleBase
{
    private static readonly string[] Accepted = ["0", "1", "2", "-1", "100", "1000"];
    public override string Name => "Numbers should be named when their meaning is not obvious";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var number in context.Root.OfKind(NodeKind.NumberLiteral))
        {
            var text = number.Text.TrimEnd('L', 'l', 'f', 'F', 'd', 'D', 'm', 'M', 'u', 'U');
            if (Accepted.Contains(text, StringComparer.Ordinal) || text.Length < 2)
                continue;
            // a literal that initialises a constant is already named
            if (number.Ancestor(NodeKind.FieldDeclaration, NodeKind.EnumMember) != null)
                continue;
            if (number.Ancestor(NodeKind.Invocation, NodeKind.If, NodeKind.Loop, NodeKind.Binary) == null)
                continue;
            context.Report(number, $"The meaning of {number.Text} is not visible here; "
                                   + "give it a name through a constant.");
            break; // one reminder per file is enough
        }
    }
}

public sealed class MagicNumberRuleCs : MagicNumberRule
{
    public override string Key => "QG-CS-SML-0498";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class MagicNumberRuleJava : MagicNumberRule
{
    public override string Key => "QG-JV-SML-0459";
    public override string[] Languages => ["java"];
}

public sealed class MagicNumberRuleJs : MagicNumberRule
{
    public override string Key => "QG-JS-SML-0375";
    public override string[] Languages => ["js", "ts"];
}

public sealed class MagicNumberRulePython : MagicNumberRule
{
    public override string Key => "QG-PY-SML-0254";
    public override string[] Languages => ["py"];
}

public sealed class MagicNumberRulePhp : MagicNumberRule
{
    public override string Key => "QG-PP-SML-0119";
    public override string[] Languages => ["php"];
}

public sealed class MagicNumberRuleGo : MagicNumberRule
{
    public override string Key => "QG-GO-SML-0033";
    public override string[] Languages => ["go"];
}

public sealed class MagicNumberRuleRuby : MagicNumberRule
{
    public override string Key => "QG-RB-SML-0050";
    public override string[] Languages => ["rb"];
}

public sealed class MagicNumberRuleSwift : MagicNumberRule
{
    public override string Key => "QG-SW-SML-0034";
    public override string[] Languages => ["swift"];
}

public sealed class MagicNumberRuleCss : MagicNumberRule
{
    public override string Key => "QG-CSS-SML-0055";
    public override string[] Languages => ["css"];
}

public sealed class MagicNumberRuleHtml : MagicNumberRule
{
    public override string Key => "QG-HTML-SML-0127";
    public override string[] Languages => ["html"];
}

public sealed class MagicNumberRuleXml : MagicNumberRule
{
    public override string Key => "QG-XML-SML-0042";
    public override string[] Languages => ["xml"];
}

public sealed class MagicNumberRuleTerraform : MagicNumberRule
{
    public override string Key => "QG-TF-SML-0034";
    public override string[] Languages => ["tf"];
}

public sealed class MagicNumberRuleDockerfile : MagicNumberRule
{
    public override string Key => "QG-DK-SML-0048";
    public override string[] Languages => ["dk"];
}

public sealed class MagicNumberRuleKubernetes : MagicNumberRule
{
    public override string Key => "QG-K8-SML-0042";
    public override string[] Languages => ["k8"];
}

public sealed class MagicNumberRuleCloudFormation : MagicNumberRule
{
    public override string Key => "QG-CF-SML-0035";
    public override string[] Languages => ["cf"];
}

public sealed class MagicNumberRuleJson : MagicNumberRule
{
    public override string Key => "QG-JSON-SML-0030";
    public override string[] Languages => ["json"];
}

public sealed class MagicNumberRuleKotlin : MagicNumberRule
{
    public override string Key => "QG-KT-SML-0134";
    public override string[] Languages => ["kt"];
}

public sealed class MagicNumberRuleDart : MagicNumberRule
{
    public override string Key => "QG-DART-SML-0052";
    public override string[] Languages => ["dart"];
}

public abstract class NestedTernaryRule : StructuralRuleBase
{
    public override string Name => "Conditional expressions should not be nested";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "15min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var conditional in context.Root.OfKind(NodeKind.Conditional))
        {
            if (conditional.Ancestor(NodeKind.Conditional) == null)
                continue;
            context.Report(conditional, "A conditional inside another one hides which case applies; "
                                        + "use a statement form or extract a named helper.");
        }
    }
}

public sealed class NestedTernaryRuleCs : NestedTernaryRule
{
    public override string Key => "QG-CS-SML-0518";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class NestedTernaryRuleJava : NestedTernaryRule
{
    public override string Key => "QG-JV-SML-0479";
    public override string[] Languages => ["java"];
}

public sealed class NestedTernaryRuleKotlin : NestedTernaryRule
{
    public override string Key => "QG-KT-SML-0101";
    public override string[] Languages => ["kt"];
}

public sealed class NestedTernaryRuleJs : NestedTernaryRule
{
    public override string Key => "QG-JS-SML-0395";
    public override string[] Languages => ["js", "ts"];
}

public sealed class NestedTernaryRulePython : NestedTernaryRule
{
    public override string Key => "QG-PY-SML-0274";
    public override string[] Languages => ["py"];
}

public sealed class NestedTernaryRulePhp : NestedTernaryRule
{
    public override string Key => "QG-PP-SML-0139";
    public override string[] Languages => ["php"];
}

public sealed class NestedTernaryRuleGo : NestedTernaryRule
{
    public override string Key => "QG-GO-SML-0053";
    public override string[] Languages => ["go"];
}

public sealed class NestedTernaryRuleDart : NestedTernaryRule
{
    public override string Key => "QG-DART-SML-0018";
    public override string[] Languages => ["dart"];
}

public sealed class NestedTernaryRuleRuby : NestedTernaryRule
{
    public override string Key => "QG-RB-SML-0051";
    public override string[] Languages => ["rb"];
}

public sealed class NestedTernaryRuleSwift : NestedTernaryRule
{
    public override string Key => "QG-SW-SML-0035";
    public override string[] Languages => ["swift"];
}

public sealed class NestedTernaryRuleCss : NestedTernaryRule
{
    public override string Key => "QG-CSS-SML-0056";
    public override string[] Languages => ["css"];
}

public sealed class NestedTernaryRuleHtml : NestedTernaryRule
{
    public override string Key => "QG-HTML-SML-0128";
    public override string[] Languages => ["html"];
}

public sealed class NestedTernaryRuleXml : NestedTernaryRule
{
    public override string Key => "QG-XML-SML-0043";
    public override string[] Languages => ["xml"];
}

public sealed class NestedTernaryRuleTerraform : NestedTernaryRule
{
    public override string Key => "QG-TF-SML-0035";
    public override string[] Languages => ["tf"];
}

public sealed class NestedTernaryRuleDockerfile : NestedTernaryRule
{
    public override string Key => "QG-DK-SML-0049";
    public override string[] Languages => ["dk"];
}

public sealed class NestedTernaryRuleKubernetes : NestedTernaryRule
{
    public override string Key => "QG-K8-SML-0043";
    public override string[] Languages => ["k8"];
}

public sealed class NestedTernaryRuleCloudFormation : NestedTernaryRule
{
    public override string Key => "QG-CF-SML-0036";
    public override string[] Languages => ["cf"];
}

public sealed class NestedTernaryRuleJson : NestedTernaryRule
{
    public override string Key => "QG-JSON-SML-0031";
    public override string[] Languages => ["json"];
}

public abstract class TooManyMembersRule : StructuralRuleBase
{
    private // the reference allows thirty-five before it says a class does too much; ours said
    // twenty-five, which reported classes nobody else would
    const int MaxMethods = 35;
    private const int MaxFields = 20;
    public override string Name => "Types should not accumulate too many members";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "45min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            var methods = type.OfKind(NodeKind.FunctionDeclaration)
                .Count(m => m.Ancestor(NodeKind.ClassDeclaration) == type);
            var fields = type.OfKind(NodeKind.FieldDeclaration, NodeKind.PropertyDeclaration)
                .Count(f => f.Ancestor(NodeKind.ClassDeclaration) == type);
            if (methods <= MaxMethods && fields <= MaxFields)
                continue;
            context.Report(type, $"'{type.Text}' declares {methods} methods and {fields} fields; "
                                 + "split the responsibilities it has accumulated.");
        }
    }
}

public sealed class TooManyMembersRuleCs : TooManyMembersRule
{
    public override string Key => "QG-CS-SML-0502";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class TooManyMembersRuleJava : TooManyMembersRule
{
    public override string Key => "QG-JV-SML-0463";
    public override string[] Languages => ["java"];
}

public sealed class TooManyMembersRuleJs : TooManyMembersRule
{
    public override string Key => "QG-JS-SML-0379";
    public override string[] Languages => ["js", "ts"];
}

public sealed class TooManyMembersRulePython : TooManyMembersRule
{
    public override string Key => "QG-PY-SML-0258";
    public override string[] Languages => ["py"];
}

public sealed class TooManyMembersRulePhp : TooManyMembersRule
{
    public override string Key => "QG-PP-SML-0123";
    public override string[] Languages => ["php"];
}

public sealed class TooManyMembersRuleGo : TooManyMembersRule
{
    public override string Key => "QG-GO-SML-0037";
    public override string[] Languages => ["go"];
}

public sealed class TooManyMembersRuleRuby : TooManyMembersRule
{
    public override string Key => "QG-RB-SML-0052";
    public override string[] Languages => ["rb"];
}

public sealed class TooManyMembersRuleSwift : TooManyMembersRule
{
    public override string Key => "QG-SW-SML-0036";
    public override string[] Languages => ["swift"];
}

public sealed class TooManyMembersRuleCss : TooManyMembersRule
{
    public override string Key => "QG-CSS-SML-0057";
    public override string[] Languages => ["css"];
}

public sealed class TooManyMembersRuleHtml : TooManyMembersRule
{
    public override string Key => "QG-HTML-SML-0129";
    public override string[] Languages => ["html"];
}

public sealed class TooManyMembersRuleXml : TooManyMembersRule
{
    public override string Key => "QG-XML-SML-0044";
    public override string[] Languages => ["xml"];
}

public sealed class TooManyMembersRuleTerraform : TooManyMembersRule
{
    public override string Key => "QG-TF-SML-0036";
    public override string[] Languages => ["tf"];
}

public sealed class TooManyMembersRuleDockerfile : TooManyMembersRule
{
    public override string Key => "QG-DK-SML-0050";
    public override string[] Languages => ["dk"];
}

public sealed class TooManyMembersRuleKubernetes : TooManyMembersRule
{
    public override string Key => "QG-K8-SML-0044";
    public override string[] Languages => ["k8"];
}

public sealed class TooManyMembersRuleCloudFormation : TooManyMembersRule
{
    public override string Key => "QG-CF-SML-0037";
    public override string[] Languages => ["cf"];
}

public sealed class TooManyMembersRuleJson : TooManyMembersRule
{
    public override string Key => "QG-JSON-SML-0032";
    public override string[] Languages => ["json"];
}

public sealed class TooManyMembersRuleKotlin : TooManyMembersRule
{
    public override string Key => "QG-KT-SML-0135";
    public override string[] Languages => ["kt"];
}

public sealed class TooManyMembersRuleDart : TooManyMembersRule
{
    public override string Key => "QG-DART-SML-0053";
    public override string[] Languages => ["dart"];
}

public abstract class TestWithoutAssertionRule : StructuralRuleBase
{
    private static readonly string[] AssertionNames =
    [
        "assert", "assertthat", "assertequals", "asserttrue", "assertfalse", "assertnull",
        "assertnotnull", "expect", "should", "verify", "check", "mustbe", "throws", "assertion",
        // a test can state its expectation without the word: these throw when it does not hold
        "ensuresuccessstatuscode", "received", "musthavehappened", "shouldbe", "shouldsatisfy",
        "matchsnapshot", "approve", "isvalid", "haveoccurred",
        // Go states a failure rather than asserting a success: 't.Error', 't.Fatal' and the helpers
        // built on them are how every test in the language says the expectation did not hold
        "t.error", "t.errorf", "t.fatal", "t.fatalf", "t.fail", "t.failnow", "b.error", "b.fatal",
        "require", "equal", "nooerror", "noerror", "notnil", "notempty", "len"
    ];
    public override string Name => "Tests should verify something";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "15min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context) || !LooksLikeTestFile(context))
            return;

        foreach (var function in SyntaxQuery.Functions(context.Root))
        {
            var body = SyntaxQuery.Body(function);
            if (body is null or { Children.Count: 0 })
                continue;
            if (!IsTestName(function))
                continue;
            // The assertion is often the receiver, not the method: NUnit writes 'Assert.That',
            // xUnit 'Assert.Equal', FluentAssertions 'value.Should().Be'. Reading only the method
            // name saw 'That' and 'Be' and reported tests that assert on every line.
            var asserts = function.OfKind(NodeKind.Invocation).Any(call =>
            {
                var chain = SyntaxQuery.InvokedDottedName(call);
                if (chain.Length == 0)
                    chain = SyntaxQuery.InvokedName(call);
                var lowered = chain.ToLowerInvariant();
                return AssertionNames.Any(name => lowered.Contains(name));
            });
            // In Python and Rust the assertion is a statement, not a call: 'assert x == y' carries
            // no invocation at all, so a whole pytest suite read as tests that verify nothing.
            asserts = asserts || function.OfKind(NodeKind.Jump)
                .Any(jump => jump.Text is "assert" or "raise");
            if (asserts)
                continue;
            context.Report(function, $"'{function.Text}' runs code but asserts nothing, "
                                     + "so it passes whatever the behaviour does.");
        }
    }

    /// <summary>
    /// Whether the file is a test. It shares the judgement with the rest of the engine rather than
    /// asking whether the name contains "test": a sample under src/test/resources is data a test
    /// reads, and every one of those was being reported as a test that verifies nothing.
    /// </summary>
    private static bool LooksLikeTestFile(IRuleContext context)
        => Rules.Languages.LanguageRuleSupport.IsTestFile(context.File.Path, context.File.FileName);

    /// <summary>The annotations that declare a test, across the frameworks that use one.</summary>
    private static readonly string[] Markers =
    [
        "Test", "TestMethod", "TestCase", "TestTemplate", "Fact", "Theory", "ParameterizedTest",
        "RepeatedTest", "DataTestMethod", "TestFactory", "It", "Should"
    ];

    private static readonly string[] Scaffolding =
        ["fixture", "setup", "teardown", "before", "after", "classmethod", "staticmethod", "property"];

    private static bool IsTestName(SyntaxNode function)
    {
        // A fixture or a setup step runs so that the tests can, and asserting is not its job. It
        // sits in the same file and often in the same class, so the decorator is what tells them
        // apart — and it says so plainly even where the surrounding parse is uncertain.
        if (function.ChildrenOf(NodeKind.Attribute)
            .Any(a => Scaffolding.Any(s => a.Text.Contains(s, StringComparison.OrdinalIgnoreCase))))
            return false;

        var name = function.Text.ToLowerInvariant();
        if (name.StartsWith("test", StringComparison.Ordinal) || name.EndsWith("test", StringComparison.Ordinal))
            return true;
        // The annotation is the last part of the name, and only that part decides. Searching the
        // whole text for "test" matched 'pytest.mark.parametrize' and 'pytest.fixture', because the
        // framework has the word in its own name — so every helper in a Python suite was read as a
        // test that verifies nothing.
        return function.ChildrenOf(NodeKind.Attribute)
            .Select(a => a.Text.Split('.').Last().Split('(')[0].Trim())
            .Any(marker => Markers.Contains(marker, StringComparer.OrdinalIgnoreCase));
    }
}

public sealed class TestWithoutAssertionRuleCs : TestWithoutAssertionRule
{
    public override string Key => "QG-CS-BUG-0157";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class TestWithoutAssertionRuleJava : TestWithoutAssertionRule
{
    public override string Key => "QG-JV-BUG-0211";
    public override string[] Languages => ["java"];
}

public sealed class TestWithoutAssertionRuleKotlin : TestWithoutAssertionRule
{
    public override string Key => "QG-KT-BUG-0038";
    public override string[] Languages => ["kt"];
}

public sealed class TestWithoutAssertionRuleJs : TestWithoutAssertionRule
{
    public override string Key => "QG-JS-BUG-0155";
    public override string[] Languages => ["js", "ts"];
}

public sealed class TestWithoutAssertionRulePython : TestWithoutAssertionRule
{
    public override string Key => "QG-PY-BUG-0161";
    public override string[] Languages => ["py"];
}

public sealed class TestWithoutAssertionRulePhp : TestWithoutAssertionRule
{
    public override string Key => "QG-PP-BUG-0058";
    public override string[] Languages => ["php"];
}

public sealed class TestWithoutAssertionRuleGo : TestWithoutAssertionRule
{
    public override string Key => "QG-GO-BUG-0014";
    public override string[] Languages => ["go"];
}

public sealed class TestWithoutAssertionRuleDart : TestWithoutAssertionRule
{
    public override string Key => "QG-DART-BUG-0012";
    public override string[] Languages => ["dart"];
}

public sealed class TestWithoutAssertionRuleRuby : TestWithoutAssertionRule
{
    public override string Key => "QG-RB-BUG-0033";
    public override string[] Languages => ["rb"];
}

public sealed class TestWithoutAssertionRuleSwift : TestWithoutAssertionRule
{
    public override string Key => "QG-SW-BUG-0037";
    public override string[] Languages => ["swift"];
}

public sealed class TestWithoutAssertionRuleCss : TestWithoutAssertionRule
{
    public override string Key => "QG-CSS-BUG-0062";
    public override string[] Languages => ["css"];
}

public sealed class TestWithoutAssertionRuleHtml : TestWithoutAssertionRule
{
    public override string Key => "QG-HTML-BUG-0062";
    public override string[] Languages => ["html"];
}

public sealed class TestWithoutAssertionRuleXml : TestWithoutAssertionRule
{
    public override string Key => "QG-XML-BUG-0037";
    public override string[] Languages => ["xml"];
}

public sealed class TestWithoutAssertionRuleTerraform : TestWithoutAssertionRule
{
    public override string Key => "QG-TF-BUG-0032";
    public override string[] Languages => ["tf"];
}

public sealed class TestWithoutAssertionRuleDockerfile : TestWithoutAssertionRule
{
    public override string Key => "QG-DK-BUG-0039";
    public override string[] Languages => ["dk"];
}

public sealed class TestWithoutAssertionRuleKubernetes : TestWithoutAssertionRule
{
    public override string Key => "QG-K8-BUG-0032";
    public override string[] Languages => ["k8"];
}

public sealed class TestWithoutAssertionRuleCloudFormation : TestWithoutAssertionRule
{
    public override string Key => "QG-CF-BUG-0032";
    public override string[] Languages => ["cf"];
}

public sealed class TestWithoutAssertionRuleJson : TestWithoutAssertionRule
{
    public override string Key => "QG-JSON-BUG-0033";
    public override string[] Languages => ["json"];
}

public abstract class GenericExceptionCaughtRule : StructuralRuleBase
{
    private static readonly string[] BaseTypes =
        ["Exception", "SystemException", "Throwable", "Error", "BaseException", "RuntimeException"];
    public override string Name => "Catch clauses should name the failures they handle";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "15min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var handler in context.Root.OfKind(NodeKind.Catch))
        {
            var type = handler.FirstChild(NodeKind.TypeReference)?.Text
                       ?? handler.FirstChild(NodeKind.Pattern)?.Text;
            if (type == null || !BaseTypes.Contains(type, StringComparer.Ordinal))
                continue;
            if (handler.Ancestor(NodeKind.FunctionDeclaration) is { Text: "Main" or "main" })
                continue; // the process boundary may legitimately catch everything
            context.Report(handler, $"Catching '{type}' also swallows the failures this code cannot "
                                    + "handle; catch the specific ones and let the rest reach the boundary.");
        }
    }
}

public sealed class GenericExceptionCaughtRuleCs : GenericExceptionCaughtRule
{
    public override string Key => "QG-CS-SML-0519";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class GenericExceptionCaughtRuleJava : GenericExceptionCaughtRule
{
    public override string Key => "QG-JV-SML-0480";
    public override string[] Languages => ["java"];
}

public sealed class GenericExceptionCaughtRuleKotlin : GenericExceptionCaughtRule
{
    public override string Key => "QG-KT-SML-0102";
    public override string[] Languages => ["kt"];
}

public sealed class GenericExceptionCaughtRuleJs : GenericExceptionCaughtRule
{
    public override string Key => "QG-JS-SML-0396";
    public override string[] Languages => ["js", "ts"];
}

public sealed class GenericExceptionCaughtRulePython : GenericExceptionCaughtRule
{
    public override string Key => "QG-PY-SML-0275";
    public override string[] Languages => ["py"];
}

public sealed class GenericExceptionCaughtRulePhp : GenericExceptionCaughtRule
{
    public override string Key => "QG-PP-SML-0140";
    public override string[] Languages => ["php"];
}

public sealed class GenericExceptionCaughtRuleGo : GenericExceptionCaughtRule
{
    public override string Key => "QG-GO-SML-0054";
    public override string[] Languages => ["go"];
}

public sealed class GenericExceptionCaughtRuleDart : GenericExceptionCaughtRule
{
    public override string Key => "QG-DART-SML-0019";
    public override string[] Languages => ["dart"];
}

public sealed class GenericExceptionCaughtRuleRuby : GenericExceptionCaughtRule
{
    public override string Key => "QG-RB-SML-0053";
    public override string[] Languages => ["rb"];
}

public sealed class GenericExceptionCaughtRuleSwift : GenericExceptionCaughtRule
{
    public override string Key => "QG-SW-SML-0037";
    public override string[] Languages => ["swift"];
}

public sealed class GenericExceptionCaughtRuleCss : GenericExceptionCaughtRule
{
    public override string Key => "QG-CSS-SML-0058";
    public override string[] Languages => ["css"];
}

public sealed class GenericExceptionCaughtRuleHtml : GenericExceptionCaughtRule
{
    public override string Key => "QG-HTML-SML-0130";
    public override string[] Languages => ["html"];
}

public sealed class GenericExceptionCaughtRuleXml : GenericExceptionCaughtRule
{
    public override string Key => "QG-XML-SML-0045";
    public override string[] Languages => ["xml"];
}

public sealed class GenericExceptionCaughtRuleTerraform : GenericExceptionCaughtRule
{
    public override string Key => "QG-TF-SML-0037";
    public override string[] Languages => ["tf"];
}

public sealed class GenericExceptionCaughtRuleDockerfile : GenericExceptionCaughtRule
{
    public override string Key => "QG-DK-SML-0051";
    public override string[] Languages => ["dk"];
}

public sealed class GenericExceptionCaughtRuleKubernetes : GenericExceptionCaughtRule
{
    public override string Key => "QG-K8-SML-0045";
    public override string[] Languages => ["k8"];
}

public sealed class GenericExceptionCaughtRuleCloudFormation : GenericExceptionCaughtRule
{
    public override string Key => "QG-CF-SML-0038";
    public override string[] Languages => ["cf"];
}

public sealed class GenericExceptionCaughtRuleJson : GenericExceptionCaughtRule
{
    public override string Key => "QG-JSON-SML-0033";
    public override string[] Languages => ["json"];
}

public abstract class GenericExceptionThrownRule : StructuralRuleBase
{
    private static readonly string[] BaseTypes =
        ["Exception", "SystemException", "Throwable", "Error", "RuntimeException", "BaseException"];
    public override string Name => "Thrown exceptions should be specific";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "15min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var jump in context.Root.OfKind(NodeKind.Jump))
        {
            if (jump.Text is not ("throw" or "raise"))
                continue;
            var created = jump.OfKind(NodeKind.ObjectCreation).FirstOrDefault()
                          ?? jump.OfKind(NodeKind.Invocation).FirstOrDefault();
            var type = created?.Text ?? string.Empty;
            if (!BaseTypes.Contains(type, StringComparer.Ordinal))
                continue;
            context.Report(jump, $"'{type}' tells the caller nothing about the failure; "
                                 + "throw a specific type it can act on.");
        }
    }
}

public sealed class GenericExceptionThrownRuleCs : GenericExceptionThrownRule
{
    public override string Key => "QG-CS-SML-0520";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class GenericExceptionThrownRuleJava : GenericExceptionThrownRule
{
    public override string Key => "QG-JV-SML-0481";
    public override string[] Languages => ["java"];
}

public sealed class GenericExceptionThrownRuleKotlin : GenericExceptionThrownRule
{
    public override string Key => "QG-KT-SML-0103";
    public override string[] Languages => ["kt"];
}

public sealed class GenericExceptionThrownRuleJs : GenericExceptionThrownRule
{
    public override string Key => "QG-JS-SML-0397";
    public override string[] Languages => ["js", "ts"];
}

public sealed class GenericExceptionThrownRulePython : GenericExceptionThrownRule
{
    public override string Key => "QG-PY-SML-0276";
    public override string[] Languages => ["py"];
}

public sealed class GenericExceptionThrownRulePhp : GenericExceptionThrownRule
{
    public override string Key => "QG-PP-SML-0141";
    public override string[] Languages => ["php"];
}

public sealed class GenericExceptionThrownRuleGo : GenericExceptionThrownRule
{
    public override string Key => "QG-GO-SML-0055";
    public override string[] Languages => ["go"];
}

public sealed class GenericExceptionThrownRuleDart : GenericExceptionThrownRule
{
    public override string Key => "QG-DART-SML-0020";
    public override string[] Languages => ["dart"];
}

public sealed class GenericExceptionThrownRuleRuby : GenericExceptionThrownRule
{
    public override string Key => "QG-RB-SML-0054";
    public override string[] Languages => ["rb"];
}

public sealed class GenericExceptionThrownRuleSwift : GenericExceptionThrownRule
{
    public override string Key => "QG-SW-SML-0038";
    public override string[] Languages => ["swift"];
}

public sealed class GenericExceptionThrownRuleCss : GenericExceptionThrownRule
{
    public override string Key => "QG-CSS-SML-0059";
    public override string[] Languages => ["css"];
}

public sealed class GenericExceptionThrownRuleHtml : GenericExceptionThrownRule
{
    public override string Key => "QG-HTML-SML-0131";
    public override string[] Languages => ["html"];
}

public sealed class GenericExceptionThrownRuleXml : GenericExceptionThrownRule
{
    public override string Key => "QG-XML-SML-0046";
    public override string[] Languages => ["xml"];
}

public sealed class GenericExceptionThrownRuleTerraform : GenericExceptionThrownRule
{
    public override string Key => "QG-TF-SML-0038";
    public override string[] Languages => ["tf"];
}

public sealed class GenericExceptionThrownRuleDockerfile : GenericExceptionThrownRule
{
    public override string Key => "QG-DK-SML-0052";
    public override string[] Languages => ["dk"];
}

public sealed class GenericExceptionThrownRuleKubernetes : GenericExceptionThrownRule
{
    public override string Key => "QG-K8-SML-0046";
    public override string[] Languages => ["k8"];
}

public sealed class GenericExceptionThrownRuleCloudFormation : GenericExceptionThrownRule
{
    public override string Key => "QG-CF-SML-0039";
    public override string[] Languages => ["cf"];
}

public sealed class GenericExceptionThrownRuleJson : GenericExceptionThrownRule
{
    public override string Key => "QG-JSON-SML-0034";
    public override string[] Languages => ["json"];
}

public abstract class RethrowLosingStackRule : StructuralRuleBase
{
    public override string Name => "Rethrowing should preserve the original trace";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context) || context.Language.LanguageKey is not ("cs" or "vb"))
            return;

        foreach (var handler in context.Root.OfKind(NodeKind.Catch))
        {
            var caught = handler.FirstChild(NodeKind.VariableDeclaration)?.Text;
            if (string.IsNullOrEmpty(caught))
                continue;
            foreach (var jump in handler.OfKind(NodeKind.Jump).Where(j => j.Text == "throw"))
            {
                var thrown = SyntaxQuery.DottedName(jump.ChildAt(0));
                if (thrown != caught)
                    continue;
                context.Report(jump, $"Throwing '{caught}' again restarts the stack trace here; "
                                     + "use a bare throw, or wrap it as the inner exception.");
            }
        }
    }
}

public sealed class RethrowLosingStackRuleCs : RethrowLosingStackRule
{
    public override string Key => "QG-CS-BUG-0158";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class RethrowLosingStackRuleJava : RethrowLosingStackRule
{
    public override string Key => "QG-JV-BUG-0212";
    public override string[] Languages => ["java"];
}

public sealed class RethrowLosingStackRuleKotlin : RethrowLosingStackRule
{
    public override string Key => "QG-KT-BUG-0039";
    public override string[] Languages => ["kt"];
}

public sealed class RethrowLosingStackRuleJs : RethrowLosingStackRule
{
    public override string Key => "QG-JS-BUG-0156";
    public override string[] Languages => ["js", "ts"];
}

public sealed class RethrowLosingStackRulePython : RethrowLosingStackRule
{
    public override string Key => "QG-PY-BUG-0162";
    public override string[] Languages => ["py"];
}

public sealed class RethrowLosingStackRulePhp : RethrowLosingStackRule
{
    public override string Key => "QG-PP-BUG-0059";
    public override string[] Languages => ["php"];
}

public sealed class RethrowLosingStackRuleGo : RethrowLosingStackRule
{
    public override string Key => "QG-GO-BUG-0015";
    public override string[] Languages => ["go"];
}

public sealed class RethrowLosingStackRuleDart : RethrowLosingStackRule
{
    public override string Key => "QG-DART-BUG-0013";
    public override string[] Languages => ["dart"];
}

public sealed class RethrowLosingStackRuleRuby : RethrowLosingStackRule
{
    public override string Key => "QG-RB-BUG-0034";
    public override string[] Languages => ["rb"];
}

public sealed class RethrowLosingStackRuleSwift : RethrowLosingStackRule
{
    public override string Key => "QG-SW-BUG-0038";
    public override string[] Languages => ["swift"];
}

public sealed class RethrowLosingStackRuleCss : RethrowLosingStackRule
{
    public override string Key => "QG-CSS-BUG-0063";
    public override string[] Languages => ["css"];
}

public sealed class RethrowLosingStackRuleHtml : RethrowLosingStackRule
{
    public override string Key => "QG-HTML-BUG-0063";
    public override string[] Languages => ["html"];
}

public sealed class RethrowLosingStackRuleXml : RethrowLosingStackRule
{
    public override string Key => "QG-XML-BUG-0038";
    public override string[] Languages => ["xml"];
}

public sealed class RethrowLosingStackRuleTerraform : RethrowLosingStackRule
{
    public override string Key => "QG-TF-BUG-0033";
    public override string[] Languages => ["tf"];
}

public sealed class RethrowLosingStackRuleDockerfile : RethrowLosingStackRule
{
    public override string Key => "QG-DK-BUG-0040";
    public override string[] Languages => ["dk"];
}

public sealed class RethrowLosingStackRuleKubernetes : RethrowLosingStackRule
{
    public override string Key => "QG-K8-BUG-0033";
    public override string[] Languages => ["k8"];
}

public sealed class RethrowLosingStackRuleCloudFormation : RethrowLosingStackRule
{
    public override string Key => "QG-CF-BUG-0033";
    public override string[] Languages => ["cf"];
}

public sealed class RethrowLosingStackRuleJson : RethrowLosingStackRule
{
    public override string Key => "QG-JSON-BUG-0034";
    public override string[] Languages => ["json"];
}

public abstract class JumpInFinallyRule : StructuralRuleBase
{
    public override string Name => "Cleanup blocks should not change the control flow";
    public override Severity Severity => Severity.Blocker;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "20min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var cleanup in context.Root.OfKind(NodeKind.Finally))
        {
            foreach (var jump in cleanup.OfKind(NodeKind.Jump))
            {
                if (jump.Text is not ("return" or "break" or "continue" or "throw" or "raise"))
                    continue;
                if (jump.Ancestor(NodeKind.Lambda, NodeKind.FunctionDeclaration) is { } inner
                    && inner.Ancestor(NodeKind.Finally) == null)
                    continue; // belongs to a nested function, not to the cleanup itself
                context.Report(jump, $"'{jump.Text}' inside cleanup discards whatever was in flight, "
                                     + "including an exception on its way to the caller.");
                break;
            }
        }
    }
}

public sealed class JumpInFinallyRuleCs : JumpInFinallyRule
{
    public override string Key => "QG-CS-BUG-0159";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class JumpInFinallyRuleJava : JumpInFinallyRule
{
    public override string Key => "QG-JV-BUG-0213";
    public override string[] Languages => ["java"];
}

public sealed class JumpInFinallyRuleKotlin : JumpInFinallyRule
{
    public override string Key => "QG-KT-BUG-0040";
    public override string[] Languages => ["kt"];
}

public sealed class JumpInFinallyRuleJs : JumpInFinallyRule
{
    public override string Key => "QG-JS-BUG-0157";
    public override string[] Languages => ["js", "ts"];
}

public sealed class JumpInFinallyRulePython : JumpInFinallyRule
{
    public override string Key => "QG-PY-BUG-0163";
    public override string[] Languages => ["py"];
}

public sealed class JumpInFinallyRulePhp : JumpInFinallyRule
{
    public override string Key => "QG-PP-BUG-0060";
    public override string[] Languages => ["php"];
}

public sealed class JumpInFinallyRuleGo : JumpInFinallyRule
{
    public override string Key => "QG-GO-BUG-0016";
    public override string[] Languages => ["go"];
}

public sealed class JumpInFinallyRuleDart : JumpInFinallyRule
{
    public override string Key => "QG-DART-BUG-0014";
    public override string[] Languages => ["dart"];
}

public sealed class JumpInFinallyRuleRuby : JumpInFinallyRule
{
    public override string Key => "QG-RB-BUG-0035";
    public override string[] Languages => ["rb"];
}

public sealed class JumpInFinallyRuleSwift : JumpInFinallyRule
{
    public override string Key => "QG-SW-BUG-0039";
    public override string[] Languages => ["swift"];
}

public sealed class JumpInFinallyRuleCss : JumpInFinallyRule
{
    public override string Key => "QG-CSS-BUG-0064";
    public override string[] Languages => ["css"];
}

public sealed class JumpInFinallyRuleHtml : JumpInFinallyRule
{
    public override string Key => "QG-HTML-BUG-0064";
    public override string[] Languages => ["html"];
}

public sealed class JumpInFinallyRuleXml : JumpInFinallyRule
{
    public override string Key => "QG-XML-BUG-0039";
    public override string[] Languages => ["xml"];
}

public sealed class JumpInFinallyRuleTerraform : JumpInFinallyRule
{
    public override string Key => "QG-TF-BUG-0034";
    public override string[] Languages => ["tf"];
}

public sealed class JumpInFinallyRuleDockerfile : JumpInFinallyRule
{
    public override string Key => "QG-DK-BUG-0041";
    public override string[] Languages => ["dk"];
}

public sealed class JumpInFinallyRuleKubernetes : JumpInFinallyRule
{
    public override string Key => "QG-K8-BUG-0034";
    public override string[] Languages => ["k8"];
}

public sealed class JumpInFinallyRuleCloudFormation : JumpInFinallyRule
{
    public override string Key => "QG-CF-BUG-0034";
    public override string[] Languages => ["cf"];
}

public sealed class JumpInFinallyRuleJson : JumpInFinallyRule
{
    public override string Key => "QG-JSON-BUG-0035";
    public override string[] Languages => ["json"];
}

public abstract class LockOnSharedObjectRule : StructuralRuleBase
{
    public override string Name => "Locks should be taken on a private object";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "20min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var lockStatement in context.Root.OfKind(NodeKind.Lock))
        {
            var subject = lockStatement.Children.FirstOrDefault(c => c.Kind is not NodeKind.Block);
            if (subject == null)
                continue;
            var text = SyntaxQuery.DottedName(subject);
            var isShared = subject.Kind == NodeKind.StringLiteral
                           || text is "this" or "self"
                           || text.StartsWith("typeof", StringComparison.Ordinal)
                           || subject.OfKind(NodeKind.Invocation).Any(i =>
                               SyntaxQuery.InvokedName(i) is "getClass" or "typeof" or "GetType");
            if (!isShared)
                continue;
            context.Report(lockStatement, "Anything reachable from outside can lock this monitor too, "
                                          + "so unrelated code can block or deadlock this section; "
                                          + "use a private object dedicated to the state it protects.");
        }
    }
}

public sealed class LockOnSharedObjectRuleCs : LockOnSharedObjectRule
{
    public override string Key => "QG-CS-BUG-0160";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class LockOnSharedObjectRuleJava : LockOnSharedObjectRule
{
    public override string Key => "QG-JV-BUG-0214";
    public override string[] Languages => ["java"];
}

public sealed class LockOnSharedObjectRuleKotlin : LockOnSharedObjectRule
{
    public override string Key => "QG-KT-BUG-0041";
    public override string[] Languages => ["kt"];
}

public sealed class LockOnSharedObjectRuleJs : LockOnSharedObjectRule
{
    public override string Key => "QG-JS-BUG-0158";
    public override string[] Languages => ["js", "ts"];
}

public sealed class LockOnSharedObjectRulePython : LockOnSharedObjectRule
{
    public override string Key => "QG-PY-BUG-0164";
    public override string[] Languages => ["py"];
}

public sealed class LockOnSharedObjectRulePhp : LockOnSharedObjectRule
{
    public override string Key => "QG-PP-BUG-0061";
    public override string[] Languages => ["php"];
}

public sealed class LockOnSharedObjectRuleGo : LockOnSharedObjectRule
{
    public override string Key => "QG-GO-BUG-0017";
    public override string[] Languages => ["go"];
}

public sealed class LockOnSharedObjectRuleDart : LockOnSharedObjectRule
{
    public override string Key => "QG-DART-BUG-0015";
    public override string[] Languages => ["dart"];
}

public sealed class LockOnSharedObjectRuleRuby : LockOnSharedObjectRule
{
    public override string Key => "QG-RB-BUG-0036";
    public override string[] Languages => ["rb"];
}

public sealed class LockOnSharedObjectRuleSwift : LockOnSharedObjectRule
{
    public override string Key => "QG-SW-BUG-0040";
    public override string[] Languages => ["swift"];
}

public sealed class LockOnSharedObjectRuleCss : LockOnSharedObjectRule
{
    public override string Key => "QG-CSS-BUG-0065";
    public override string[] Languages => ["css"];
}

public sealed class LockOnSharedObjectRuleHtml : LockOnSharedObjectRule
{
    public override string Key => "QG-HTML-BUG-0065";
    public override string[] Languages => ["html"];
}

public sealed class LockOnSharedObjectRuleXml : LockOnSharedObjectRule
{
    public override string Key => "QG-XML-BUG-0040";
    public override string[] Languages => ["xml"];
}

public sealed class LockOnSharedObjectRuleTerraform : LockOnSharedObjectRule
{
    public override string Key => "QG-TF-BUG-0035";
    public override string[] Languages => ["tf"];
}

public sealed class LockOnSharedObjectRuleDockerfile : LockOnSharedObjectRule
{
    public override string Key => "QG-DK-BUG-0042";
    public override string[] Languages => ["dk"];
}

public sealed class LockOnSharedObjectRuleKubernetes : LockOnSharedObjectRule
{
    public override string Key => "QG-K8-BUG-0035";
    public override string[] Languages => ["k8"];
}

public sealed class LockOnSharedObjectRuleCloudFormation : LockOnSharedObjectRule
{
    public override string Key => "QG-CF-BUG-0035";
    public override string[] Languages => ["cf"];
}

public sealed class LockOnSharedObjectRuleJson : LockOnSharedObjectRule
{
    public override string Key => "QG-JSON-BUG-0036";
    public override string[] Languages => ["json"];
}

public abstract class IgnoredTestRule : StructuralRuleBase
{
    private static readonly string[] Markers =
        ["Ignore", "Skip", "Skipped", "Disabled", "Pending", "Xfail", "Todo"];
    public override string Name => "Disabled tests should not stay in the suite";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "15min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var function in SyntaxQuery.Functions(context.Root))
        {
            var marker = function.ChildrenOf(NodeKind.Attribute)
                .FirstOrDefault(a => Markers.Any(m => a.Text.Contains(m, StringComparison.OrdinalIgnoreCase)));
            if (marker == null)
                continue;
            context.Report(function, $"'{function.Text}' is disabled, so the behaviour it covers is "
                                     + "unverified while the suite still reports green.");
        }
    }
}

public sealed class IgnoredTestRuleCs : IgnoredTestRule
{
    public override string Key => "QG-CS-SML-0521";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class IgnoredTestRuleJava : IgnoredTestRule
{
    public override string Key => "QG-JV-SML-0482";
    public override string[] Languages => ["java"];
}

public sealed class IgnoredTestRuleKotlin : IgnoredTestRule
{
    public override string Key => "QG-KT-SML-0104";
    public override string[] Languages => ["kt"];
}

public sealed class IgnoredTestRuleJs : IgnoredTestRule
{
    public override string Key => "QG-JS-SML-0398";
    public override string[] Languages => ["js", "ts"];
}

public sealed class IgnoredTestRulePython : IgnoredTestRule
{
    public override string Key => "QG-PY-SML-0277";
    public override string[] Languages => ["py"];
}

public sealed class IgnoredTestRulePhp : IgnoredTestRule
{
    public override string Key => "QG-PP-SML-0142";
    public override string[] Languages => ["php"];
}

public sealed class IgnoredTestRuleGo : IgnoredTestRule
{
    public override string Key => "QG-GO-SML-0056";
    public override string[] Languages => ["go"];
}

public sealed class IgnoredTestRuleDart : IgnoredTestRule
{
    public override string Key => "QG-DART-SML-0021";
    public override string[] Languages => ["dart"];
}

public sealed class IgnoredTestRuleRuby : IgnoredTestRule
{
    public override string Key => "QG-RB-SML-0055";
    public override string[] Languages => ["rb"];
}

public sealed class IgnoredTestRuleSwift : IgnoredTestRule
{
    public override string Key => "QG-SW-SML-0039";
    public override string[] Languages => ["swift"];
}

public sealed class IgnoredTestRuleCss : IgnoredTestRule
{
    public override string Key => "QG-CSS-SML-0060";
    public override string[] Languages => ["css"];
}

public sealed class IgnoredTestRuleHtml : IgnoredTestRule
{
    public override string Key => "QG-HTML-SML-0132";
    public override string[] Languages => ["html"];
}

public sealed class IgnoredTestRuleXml : IgnoredTestRule
{
    public override string Key => "QG-XML-SML-0047";
    public override string[] Languages => ["xml"];
}

public sealed class IgnoredTestRuleTerraform : IgnoredTestRule
{
    public override string Key => "QG-TF-SML-0039";
    public override string[] Languages => ["tf"];
}

public sealed class IgnoredTestRuleDockerfile : IgnoredTestRule
{
    public override string Key => "QG-DK-SML-0053";
    public override string[] Languages => ["dk"];
}

public sealed class IgnoredTestRuleKubernetes : IgnoredTestRule
{
    public override string Key => "QG-K8-SML-0047";
    public override string[] Languages => ["k8"];
}

public sealed class IgnoredTestRuleCloudFormation : IgnoredTestRule
{
    public override string Key => "QG-CF-SML-0040";
    public override string[] Languages => ["cf"];
}

public sealed class IgnoredTestRuleJson : IgnoredTestRule
{
    public override string Key => "QG-JSON-SML-0035";
    public override string[] Languages => ["json"];
}

public abstract class UnusedPrivateFunctionRule : StructuralRuleBase
{
    public override string Name => "Private functions should be called";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        var called = context.Root.OfKind(NodeKind.Invocation)
            .Select(SyntaxQuery.InvokedName)
            .ToHashSet(StringComparer.Ordinal);

        // when the whole project was indexed, QG-ALL-SML-0032 answers the same question with more
        // evidence; running both would report one declaration twice
        var projectWideRuleApplies = context.Project.Types.Count > 0;

        foreach (var function in SyntaxQuery.Functions(context.Root))
        {
            var declaredPrivate = function.ChildrenOf(NodeKind.Modifier).Any(m => m.Text == "private");
            var privateByConvention = context.Language.LanguageKey == "py" && function.Text.StartsWith('_')
                                      && !function.Text.StartsWith("__", StringComparison.Ordinal);
            if (declaredPrivate && projectWideRuleApplies)
                continue;
            var isPrivate = declaredPrivate || privateByConvention;
            if (!isPrivate || function.Text.Length == 0 || called.Contains(function.Text))
                continue;
            // a member referenced without a call, for instance as a delegate, still counts as used
            var referenced = context.Root.OfKind(NodeKind.Identifier)
                .Count(i => i.Text == function.Text) > 0;
            if (referenced)
                continue;
            context.Report(function, $"Nothing in this file calls '{function.Text}'; "
                                     + "remove it or make the caller explicit.");
        }
    }
}

public sealed class UnusedPrivateFunctionRuleCs : UnusedPrivateFunctionRule
{
    public override string Key => "QG-CS-SML-0522";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class UnusedPrivateFunctionRuleJava : UnusedPrivateFunctionRule
{
    public override string Key => "QG-JV-SML-0483";
    public override string[] Languages => ["java"];
}

public sealed class UnusedPrivateFunctionRuleKotlin : UnusedPrivateFunctionRule
{
    public override string Key => "QG-KT-SML-0105";
    public override string[] Languages => ["kt"];
}

public sealed class UnusedPrivateFunctionRuleJs : UnusedPrivateFunctionRule
{
    public override string Key => "QG-JS-SML-0399";
    public override string[] Languages => ["js", "ts"];
}

public sealed class UnusedPrivateFunctionRulePython : UnusedPrivateFunctionRule
{
    public override string Key => "QG-PY-SML-0278";
    public override string[] Languages => ["py"];
}

public sealed class UnusedPrivateFunctionRulePhp : UnusedPrivateFunctionRule
{
    public override string Key => "QG-PP-SML-0143";
    public override string[] Languages => ["php"];
}

public sealed class UnusedPrivateFunctionRuleGo : UnusedPrivateFunctionRule
{
    public override string Key => "QG-GO-SML-0057";
    public override string[] Languages => ["go"];
}

public sealed class UnusedPrivateFunctionRuleDart : UnusedPrivateFunctionRule
{
    public override string Key => "QG-DART-SML-0022";
    public override string[] Languages => ["dart"];
}

public sealed class UnusedPrivateFunctionRuleRuby : UnusedPrivateFunctionRule
{
    public override string Key => "QG-RB-SML-0056";
    public override string[] Languages => ["rb"];
}

public sealed class UnusedPrivateFunctionRuleSwift : UnusedPrivateFunctionRule
{
    public override string Key => "QG-SW-SML-0040";
    public override string[] Languages => ["swift"];
}

public sealed class UnusedPrivateFunctionRuleCss : UnusedPrivateFunctionRule
{
    public override string Key => "QG-CSS-SML-0061";
    public override string[] Languages => ["css"];
}

public sealed class UnusedPrivateFunctionRuleHtml : UnusedPrivateFunctionRule
{
    public override string Key => "QG-HTML-SML-0133";
    public override string[] Languages => ["html"];
}

public sealed class UnusedPrivateFunctionRuleXml : UnusedPrivateFunctionRule
{
    public override string Key => "QG-XML-SML-0048";
    public override string[] Languages => ["xml"];
}

public sealed class UnusedPrivateFunctionRuleTerraform : UnusedPrivateFunctionRule
{
    public override string Key => "QG-TF-SML-0040";
    public override string[] Languages => ["tf"];
}

public sealed class UnusedPrivateFunctionRuleDockerfile : UnusedPrivateFunctionRule
{
    public override string Key => "QG-DK-SML-0054";
    public override string[] Languages => ["dk"];
}

public sealed class UnusedPrivateFunctionRuleKubernetes : UnusedPrivateFunctionRule
{
    public override string Key => "QG-K8-SML-0048";
    public override string[] Languages => ["k8"];
}

public sealed class UnusedPrivateFunctionRuleCloudFormation : UnusedPrivateFunctionRule
{
    public override string Key => "QG-CF-SML-0041";
    public override string[] Languages => ["cf"];
}

public sealed class UnusedPrivateFunctionRuleJson : UnusedPrivateFunctionRule
{
    public override string Key => "QG-JSON-SML-0036";
    public override string[] Languages => ["json"];
}

public abstract class RedundantJumpRule : StructuralRuleBase
{
    public override string Name => "Jumps that change nothing should be removed";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var block in Blocks(context))
        {
            if (block.Children.Count == 0)
                continue;
            var last = block.Children[^1];
            if (last.Kind != NodeKind.Jump || last.Children.Count > 0)
                continue;

            var owner = block.Parent;
            var redundant = last.Text switch
            {
                "return" => owner?.Kind == NodeKind.FunctionDeclaration,
                "continue" => owner?.Kind == NodeKind.Loop,
                _ => false
            };
            if (!redundant)
                continue;
            context.Report(last, $"Control leaves the block here anyway, so this '{last.Text}' "
                                 + "only adds a line to read.");
        }
    }
}

public sealed class RedundantJumpRuleCs : RedundantJumpRule
{
    public override string Key => "QG-CS-SML-0523";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class RedundantJumpRuleJava : RedundantJumpRule
{
    public override string Key => "QG-JV-SML-0484";
    public override string[] Languages => ["java"];
}

public sealed class RedundantJumpRuleKotlin : RedundantJumpRule
{
    public override string Key => "QG-KT-SML-0106";
    public override string[] Languages => ["kt"];
}

public sealed class RedundantJumpRuleJs : RedundantJumpRule
{
    public override string Key => "QG-JS-SML-0400";
    public override string[] Languages => ["js", "ts"];
}

public sealed class RedundantJumpRulePython : RedundantJumpRule
{
    public override string Key => "QG-PY-SML-0279";
    public override string[] Languages => ["py"];
}

public sealed class RedundantJumpRulePhp : RedundantJumpRule
{
    public override string Key => "QG-PP-SML-0144";
    public override string[] Languages => ["php"];
}

public sealed class RedundantJumpRuleGo : RedundantJumpRule
{
    public override string Key => "QG-GO-SML-0058";
    public override string[] Languages => ["go"];
}

public sealed class RedundantJumpRuleDart : RedundantJumpRule
{
    public override string Key => "QG-DART-SML-0023";
    public override string[] Languages => ["dart"];
}

public sealed class RedundantJumpRuleRuby : RedundantJumpRule
{
    public override string Key => "QG-RB-SML-0057";
    public override string[] Languages => ["rb"];
}

public sealed class RedundantJumpRuleSwift : RedundantJumpRule
{
    public override string Key => "QG-SW-SML-0041";
    public override string[] Languages => ["swift"];
}

public sealed class RedundantJumpRuleCss : RedundantJumpRule
{
    public override string Key => "QG-CSS-SML-0062";
    public override string[] Languages => ["css"];
}

public sealed class RedundantJumpRuleHtml : RedundantJumpRule
{
    public override string Key => "QG-HTML-SML-0134";
    public override string[] Languages => ["html"];
}

public sealed class RedundantJumpRuleXml : RedundantJumpRule
{
    public override string Key => "QG-XML-SML-0049";
    public override string[] Languages => ["xml"];
}

public sealed class RedundantJumpRuleTerraform : RedundantJumpRule
{
    public override string Key => "QG-TF-SML-0041";
    public override string[] Languages => ["tf"];
}

public sealed class RedundantJumpRuleDockerfile : RedundantJumpRule
{
    public override string Key => "QG-DK-SML-0055";
    public override string[] Languages => ["dk"];
}

public sealed class RedundantJumpRuleKubernetes : RedundantJumpRule
{
    public override string Key => "QG-K8-SML-0049";
    public override string[] Languages => ["k8"];
}

public sealed class RedundantJumpRuleCloudFormation : RedundantJumpRule
{
    public override string Key => "QG-CF-SML-0042";
    public override string[] Languages => ["cf"];
}

public sealed class RedundantJumpRuleJson : RedundantJumpRule
{
    public override string Key => "QG-JSON-SML-0037";
    public override string[] Languages => ["json"];
}

public abstract class CommentedOutCodeRule : StructuralRuleBase
{
    public override string Name => "Commented-out code should be deleted";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        foreach (var comment in context.Tokens.Where(t => t.Kind == Tokenization.TokenKind.Comment))
        {
            var text = comment.Text.TrimStart('/', '*', '#', '-', ' ', '\t');
            if (text.Length > 200)
                continue;
            if (text.Length < 12 && text.Trim() is not ("{" or "}" or "});" or "};"))
                continue;
            // A brace on its own is code: prose does not open blocks. So is a line that ends in a
            // terminator and carries a call, an assignment or a keyword that only code uses.
            var trimmed = text.Trim();
            // a comment that opens a control structure is code whatever it ends with
            var opensCode = trimmed.StartsWith("if (", StringComparison.Ordinal)
                            || trimmed.StartsWith("for (", StringComparison.Ordinal)
                            || trimmed.StartsWith("while (", StringComparison.Ordinal)
                            || trimmed.StartsWith("foreach (", StringComparison.Ordinal)
                            || trimmed.StartsWith("switch (", StringComparison.Ordinal)
                            || trimmed.StartsWith("else if (", StringComparison.Ordinal)
                            || trimmed.StartsWith("await ", StringComparison.Ordinal)
                            || trimmed.StartsWith("return ", StringComparison.Ordinal);
            var looksLikeCode = opensCode
                                || trimmed is "{" or "}" or "});" or "};"
                                || ((text.EndsWith(';') || text.EndsWith('{') || text.EndsWith('}'))
                                    && (text.Contains('=') || text.Contains('(')
                                        || text.Contains("return") || text.Contains("await ")
                                        || text.Contains("var ") || text.Contains("new ")));
            if (!looksLikeCode)
                continue;
            context.Report("This comment holds code that no longer runs; delete it — "
                           + "version control already keeps the history.", comment.Line);
        }
    }
}

public sealed class CommentedOutCodeRuleCs : CommentedOutCodeRule
{
    public override string Key => "QG-CS-SML-0524";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class CommentedOutCodeRuleJava : CommentedOutCodeRule
{
    public override string Key => "QG-JV-SML-0485";
    public override string[] Languages => ["java"];
}

public sealed class CommentedOutCodeRuleKotlin : CommentedOutCodeRule
{
    public override string Key => "QG-KT-SML-0107";
    public override string[] Languages => ["kt"];
}

public sealed class CommentedOutCodeRuleJs : CommentedOutCodeRule
{
    public override string Key => "QG-JS-SML-0401";
    public override string[] Languages => ["js", "ts"];
}

public sealed class CommentedOutCodeRulePython : CommentedOutCodeRule
{
    public override string Key => "QG-PY-SML-0280";
    public override string[] Languages => ["py"];
}

public sealed class CommentedOutCodeRulePhp : CommentedOutCodeRule
{
    public override string Key => "QG-PP-SML-0145";
    public override string[] Languages => ["php"];
}

public sealed class CommentedOutCodeRuleGo : CommentedOutCodeRule
{
    public override string Key => "QG-GO-SML-0059";
    public override string[] Languages => ["go"];
}

public sealed class CommentedOutCodeRuleDart : CommentedOutCodeRule
{
    public override string Key => "QG-DART-SML-0024";
    public override string[] Languages => ["dart"];
}

public sealed class CommentedOutCodeRuleRuby : CommentedOutCodeRule
{
    public override string Key => "QG-RB-SML-0058";
    public override string[] Languages => ["rb"];
}

public sealed class CommentedOutCodeRuleSwift : CommentedOutCodeRule
{
    public override string Key => "QG-SW-SML-0042";
    public override string[] Languages => ["swift"];
}

public sealed class CommentedOutCodeRuleCss : CommentedOutCodeRule
{
    public override string Key => "QG-CSS-SML-0063";
    public override string[] Languages => ["css"];
}

public sealed class CommentedOutCodeRuleHtml : CommentedOutCodeRule
{
    public override string Key => "QG-HTML-SML-0135";
    public override string[] Languages => ["html"];
}

public sealed class CommentedOutCodeRuleXml : CommentedOutCodeRule
{
    public override string Key => "QG-XML-SML-0050";
    public override string[] Languages => ["xml"];
}

public sealed class CommentedOutCodeRuleTerraform : CommentedOutCodeRule
{
    public override string Key => "QG-TF-SML-0042";
    public override string[] Languages => ["tf"];
}

public sealed class CommentedOutCodeRuleDockerfile : CommentedOutCodeRule
{
    public override string Key => "QG-DK-SML-0056";
    public override string[] Languages => ["dk"];
}

public sealed class CommentedOutCodeRuleKubernetes : CommentedOutCodeRule
{
    public override string Key => "QG-K8-SML-0050";
    public override string[] Languages => ["k8"];
}

public sealed class CommentedOutCodeRuleCloudFormation : CommentedOutCodeRule
{
    public override string Key => "QG-CF-SML-0043";
    public override string[] Languages => ["cf"];
}

public sealed class CommentedOutCodeRuleJson : CommentedOutCodeRule
{
    public override string Key => "QG-JSON-SML-0038";
    public override string[] Languages => ["json"];
}

public abstract class DeepInheritanceRule : StructuralRuleBase
{
    private const int MaxDepth = 4;
    public override string Name => "Inheritance chains should stay shallow";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "45min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            var info = context.Project.FindTypes(type.Text).FirstOrDefault(t => t.Node == type);
            if (info == null)
                continue;
            var depth = context.Project.InheritanceDepth(info);
            if (depth <= MaxDepth)
                continue;
            context.Report(type, $"'{type.Text}' sits {depth} levels down its hierarchy; "
                                 + "understanding one method means opening every ancestor.");
        }
    }
}

public sealed class DeepInheritanceRuleCs : DeepInheritanceRule
{
    public override string Key => "QG-CS-SML-0525";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class DeepInheritanceRuleJava : DeepInheritanceRule
{
    public override string Key => "QG-JV-SML-0486";
    public override string[] Languages => ["java"];
}

public sealed class DeepInheritanceRuleKotlin : DeepInheritanceRule
{
    public override string Key => "QG-KT-SML-0108";
    public override string[] Languages => ["kt"];
}

public sealed class DeepInheritanceRuleJs : DeepInheritanceRule
{
    public override string Key => "QG-JS-SML-0402";
    public override string[] Languages => ["js", "ts"];
}

public sealed class DeepInheritanceRulePython : DeepInheritanceRule
{
    public override string Key => "QG-PY-SML-0281";
    public override string[] Languages => ["py"];
}

public sealed class DeepInheritanceRulePhp : DeepInheritanceRule
{
    public override string Key => "QG-PP-SML-0146";
    public override string[] Languages => ["php"];
}

public sealed class DeepInheritanceRuleGo : DeepInheritanceRule
{
    public override string Key => "QG-GO-SML-0060";
    public override string[] Languages => ["go"];
}

public sealed class DeepInheritanceRuleDart : DeepInheritanceRule
{
    public override string Key => "QG-DART-SML-0025";
    public override string[] Languages => ["dart"];
}

public sealed class DeepInheritanceRuleRuby : DeepInheritanceRule
{
    public override string Key => "QG-RB-SML-0059";
    public override string[] Languages => ["rb"];
}

public sealed class DeepInheritanceRuleSwift : DeepInheritanceRule
{
    public override string Key => "QG-SW-SML-0043";
    public override string[] Languages => ["swift"];
}

public sealed class DeepInheritanceRuleCss : DeepInheritanceRule
{
    public override string Key => "QG-CSS-SML-0064";
    public override string[] Languages => ["css"];
}

public sealed class DeepInheritanceRuleHtml : DeepInheritanceRule
{
    public override string Key => "QG-HTML-SML-0136";
    public override string[] Languages => ["html"];
}

public sealed class DeepInheritanceRuleXml : DeepInheritanceRule
{
    public override string Key => "QG-XML-SML-0051";
    public override string[] Languages => ["xml"];
}

public sealed class DeepInheritanceRuleTerraform : DeepInheritanceRule
{
    public override string Key => "QG-TF-SML-0043";
    public override string[] Languages => ["tf"];
}

public sealed class DeepInheritanceRuleDockerfile : DeepInheritanceRule
{
    public override string Key => "QG-DK-SML-0057";
    public override string[] Languages => ["dk"];
}

public sealed class DeepInheritanceRuleKubernetes : DeepInheritanceRule
{
    public override string Key => "QG-K8-SML-0051";
    public override string[] Languages => ["k8"];
}

public sealed class DeepInheritanceRuleCloudFormation : DeepInheritanceRule
{
    public override string Key => "QG-CF-SML-0044";
    public override string[] Languages => ["cf"];
}

public sealed class DeepInheritanceRuleJson : DeepInheritanceRule
{
    public override string Key => "QG-JSON-SML-0039";
    public override string[] Languages => ["json"];
}

public abstract class HiddenBaseMemberRule : StructuralRuleBase
{
    private static readonly string[] IntentionalMarkers = ["override", "new", "virtual", "abstract", "partial"];
    public override string Name => "Members should not hide a base member by accident";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "20min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context) || context.Language.LanguageKey is not ("cs" or "java" or "kt" or "vb"))
            return;

        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            var info = context.Project.FindTypes(type.Text).FirstOrDefault(t => t.Node == type);
            if (info == null || info.BaseNames.Count == 0)
                continue;
            var inherited = context.Project.InheritedMembers(info);
            if (inherited.Count == 0)
                continue;

            foreach (var member in type.OfKind(NodeKind.FunctionDeclaration, NodeKind.PropertyDeclaration))
            {
                if (member.Ancestor(NodeKind.ClassDeclaration) != type || member.Text.Length == 0)
                    continue;
                if (!inherited.Contains(member.Text))
                    continue;
                var modifiers = member.ChildrenOf(NodeKind.Modifier).Select(m => m.Text).ToArray();
                if (modifiers.Any(m => IntentionalMarkers.Contains(m, StringComparer.Ordinal)))
                    continue;
                if (member.ChildrenOf(NodeKind.Attribute).Any(a => a.Text.Contains("Override", StringComparison.OrdinalIgnoreCase)))
                    continue;
                context.Report(member, $"'{member.Text}' already exists in a base type; "
                                       + "mark the intent with override, or rename it so the two do not clash.");
            }
        }
    }
}

public sealed class HiddenBaseMemberRuleCs : HiddenBaseMemberRule
{
    public override string Key => "QG-CS-BUG-0161";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class HiddenBaseMemberRuleJava : HiddenBaseMemberRule
{
    public override string Key => "QG-JV-BUG-0215";
    public override string[] Languages => ["java"];
}

public sealed class HiddenBaseMemberRuleKotlin : HiddenBaseMemberRule
{
    public override string Key => "QG-KT-BUG-0042";
    public override string[] Languages => ["kt"];
}

public sealed class HiddenBaseMemberRuleJs : HiddenBaseMemberRule
{
    public override string Key => "QG-JS-BUG-0159";
    public override string[] Languages => ["js", "ts"];
}

public sealed class HiddenBaseMemberRulePython : HiddenBaseMemberRule
{
    public override string Key => "QG-PY-BUG-0165";
    public override string[] Languages => ["py"];
}

public sealed class HiddenBaseMemberRulePhp : HiddenBaseMemberRule
{
    public override string Key => "QG-PP-BUG-0062";
    public override string[] Languages => ["php"];
}

public sealed class HiddenBaseMemberRuleGo : HiddenBaseMemberRule
{
    public override string Key => "QG-GO-BUG-0018";
    public override string[] Languages => ["go"];
}

public sealed class HiddenBaseMemberRuleDart : HiddenBaseMemberRule
{
    public override string Key => "QG-DART-BUG-0016";
    public override string[] Languages => ["dart"];
}

public sealed class HiddenBaseMemberRuleRuby : HiddenBaseMemberRule
{
    public override string Key => "QG-RB-BUG-0037";
    public override string[] Languages => ["rb"];
}

public sealed class HiddenBaseMemberRuleSwift : HiddenBaseMemberRule
{
    public override string Key => "QG-SW-BUG-0041";
    public override string[] Languages => ["swift"];
}

public sealed class HiddenBaseMemberRuleCss : HiddenBaseMemberRule
{
    public override string Key => "QG-CSS-BUG-0066";
    public override string[] Languages => ["css"];
}

public sealed class HiddenBaseMemberRuleHtml : HiddenBaseMemberRule
{
    public override string Key => "QG-HTML-BUG-0066";
    public override string[] Languages => ["html"];
}

public sealed class HiddenBaseMemberRuleXml : HiddenBaseMemberRule
{
    public override string Key => "QG-XML-BUG-0041";
    public override string[] Languages => ["xml"];
}

public sealed class HiddenBaseMemberRuleTerraform : HiddenBaseMemberRule
{
    public override string Key => "QG-TF-BUG-0036";
    public override string[] Languages => ["tf"];
}

public sealed class HiddenBaseMemberRuleDockerfile : HiddenBaseMemberRule
{
    public override string Key => "QG-DK-BUG-0043";
    public override string[] Languages => ["dk"];
}

public sealed class HiddenBaseMemberRuleKubernetes : HiddenBaseMemberRule
{
    public override string Key => "QG-K8-BUG-0036";
    public override string[] Languages => ["k8"];
}

public sealed class HiddenBaseMemberRuleCloudFormation : HiddenBaseMemberRule
{
    public override string Key => "QG-CF-BUG-0036";
    public override string[] Languages => ["cf"];
}

public sealed class HiddenBaseMemberRuleJson : HiddenBaseMemberRule
{
    public override string Key => "QG-JSON-BUG-0037";
    public override string[] Languages => ["json"];
}

public abstract class UnusedInternalMemberRule : StructuralRuleBase
{
    public override string Name => "Non-public members should be reachable";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context) || context.Project.Types.Count == 0)
            return;

        // A code-behind is reached from the markup beside it. When the scan did not include the
        // templates the engine cannot see those callers, and saying "nothing reaches this" would be
        // a statement about the scan rather than about the code.
        var fileName = System.IO.Path.GetFileName(context.File.Path);
        var isCodeBehind = fileName.EndsWith(".razor.cs", StringComparison.OrdinalIgnoreCase)
                           || fileName.EndsWith(".cshtml.cs", StringComparison.OrdinalIgnoreCase)
                           || fileName.EndsWith(".xaml.cs", StringComparison.OrdinalIgnoreCase)
                           || fileName.EndsWith(".aspx.cs", StringComparison.OrdinalIgnoreCase);
        if (isCodeBehind && !context.Project.SawTemplates)
            return;

        foreach (var member in context.Root.OfKind(NodeKind.FunctionDeclaration))
        {
            var modifiers = member.ChildrenOf(NodeKind.Modifier).Select(m => m.Text).ToArray();
            if (!modifiers.Contains("internal") && !modifiers.Contains("private"))
                continue;
            if (member.Text.Length == 0 || context.Project.IsCalledAnywhere(member.Text))
                continue;
            // A method group is a reference without a call: '.Select(MapDocumento)' uses the method
            // as a value. Only the identifiers the declaration itself contributes are discounted,
            // and in most languages that is none of them.
            var own = member.OfKind(NodeKind.Identifier).Count(i => i.Text == member.Text);
            if (context.Project.ReferenceCount(member.Text) > own)
                continue;
            context.Report(member, $"Nothing in the scanned code reaches '{member.Text}'; "
                                   + "remove it or make the caller explicit.");
        }
    }
}

public sealed class UnusedInternalMemberRuleCs : UnusedInternalMemberRule
{
    public override string Key => "QG-CS-SML-0526";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class UnusedInternalMemberRuleJava : UnusedInternalMemberRule
{
    public override string Key => "QG-JV-SML-0487";
    public override string[] Languages => ["java"];
}

public sealed class UnusedInternalMemberRuleKotlin : UnusedInternalMemberRule
{
    public override string Key => "QG-KT-SML-0109";
    public override string[] Languages => ["kt"];
}

public sealed class UnusedInternalMemberRuleJs : UnusedInternalMemberRule
{
    public override string Key => "QG-JS-SML-0403";
    public override string[] Languages => ["js", "ts"];
}

public sealed class UnusedInternalMemberRulePython : UnusedInternalMemberRule
{
    public override string Key => "QG-PY-SML-0282";
    public override string[] Languages => ["py"];
}

public sealed class UnusedInternalMemberRulePhp : UnusedInternalMemberRule
{
    public override string Key => "QG-PP-SML-0147";
    public override string[] Languages => ["php"];
}

public sealed class UnusedInternalMemberRuleGo : UnusedInternalMemberRule
{
    public override string Key => "QG-GO-SML-0061";
    public override string[] Languages => ["go"];
}

public sealed class UnusedInternalMemberRuleDart : UnusedInternalMemberRule
{
    public override string Key => "QG-DART-SML-0026";
    public override string[] Languages => ["dart"];
}

public sealed class UnusedInternalMemberRuleRuby : UnusedInternalMemberRule
{
    public override string Key => "QG-RB-SML-0060";
    public override string[] Languages => ["rb"];
}

public sealed class UnusedInternalMemberRuleSwift : UnusedInternalMemberRule
{
    public override string Key => "QG-SW-SML-0044";
    public override string[] Languages => ["swift"];
}

public sealed class UnusedInternalMemberRuleCss : UnusedInternalMemberRule
{
    public override string Key => "QG-CSS-SML-0065";
    public override string[] Languages => ["css"];
}

public sealed class UnusedInternalMemberRuleHtml : UnusedInternalMemberRule
{
    public override string Key => "QG-HTML-SML-0137";
    public override string[] Languages => ["html"];
}

public sealed class UnusedInternalMemberRuleXml : UnusedInternalMemberRule
{
    public override string Key => "QG-XML-SML-0052";
    public override string[] Languages => ["xml"];
}

public sealed class UnusedInternalMemberRuleTerraform : UnusedInternalMemberRule
{
    public override string Key => "QG-TF-SML-0044";
    public override string[] Languages => ["tf"];
}

public sealed class UnusedInternalMemberRuleDockerfile : UnusedInternalMemberRule
{
    public override string Key => "QG-DK-SML-0058";
    public override string[] Languages => ["dk"];
}

public sealed class UnusedInternalMemberRuleKubernetes : UnusedInternalMemberRule
{
    public override string Key => "QG-K8-SML-0052";
    public override string[] Languages => ["k8"];
}

public sealed class UnusedInternalMemberRuleCloudFormation : UnusedInternalMemberRule
{
    public override string Key => "QG-CF-SML-0045";
    public override string[] Languages => ["cf"];
}

public sealed class UnusedInternalMemberRuleJson : UnusedInternalMemberRule
{
    public override string Key => "QG-JSON-SML-0040";
    public override string[] Languages => ["json"];
}

public abstract class DuplicateTypeNameRule : StructuralRuleBase
{
    public override string Name => "Type names should be unique across the code base";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "20min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            if (type.Text.Length < 3 || !context.Project.IsDeclaredMoreThanOnce(type.Text))
                continue;
            // The same simple name in two namespaces is ordinary — Settings, Options and Handler
            // exist once per module by design, and the language keeps them apart. It only confuses a
            // reader when the two answer to the same qualified name, so that is what is compared;
            // where no namespace is declared, the folder stands in for it.
            // without a declared namespace the language itself cannot tell the two apart, which is
            // what the rule about declaring types in a namespace is for
            var here = Container(type, context.File.Path);
            if (here.Length == 0)
                continue;
            var others = context.Project.FindTypes(type.Text)
                .Where(t => t.File != context.File.Path
                            && string.Equals(Container(t.Node, t.File), here, StringComparison.OrdinalIgnoreCase))
                .Select(t => System.IO.Path.GetFileName(t.File))
                .Distinct()
                .ToArray();
            if (others.Length == 0)
                continue;
            // the message names a few of them: a list of ninety file names is not a message
            var named = string.Join(", ", others.Take(3));
            var rest = others.Length > 3 ? $" and {others.Length - 3} more files" : string.Empty;
            context.Report(type, $"'{type.Text}' is also declared in {named}{rest}, under the same "
                                 + "namespace; a reader cannot tell which one an import refers to.");
        }
    }
    /// <summary>
    /// What a type is qualified by: the namespace or package it is declared in, and the folder when
    /// the language does not declare one.
    /// </summary>
    private static string Container(SyntaxNode type, string path)
    {
        for (var node = type.Parent; node != null; node = node.Parent)
        {
            if (node.Kind == NodeKind.PackageDeclaration && node.Text.Length > 0)
                return node.Text;
        }
        // a file-scoped namespace is a sibling of the type, not its parent: it covers everything
        // written after it, so the last one declared before this type is the one it belongs to
        var root = type;
        while (root.Parent != null)
            root = root.Parent;
        var declared = root.ChildrenOf(NodeKind.PackageDeclaration)
            .Where(n => n.Range.StartLine <= type.Range.StartLine && n.Text.Length > 0)
            .Select(n => n.Text)
            .LastOrDefault();
        _ = path;
        return declared ?? string.Empty;
    }

}

public sealed class DuplicateTypeNameRuleCs : DuplicateTypeNameRule
{
    public override string Key => "QG-CS-SML-0527";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class DuplicateTypeNameRuleJava : DuplicateTypeNameRule
{
    public override string Key => "QG-JV-SML-0488";
    public override string[] Languages => ["java"];
}

public sealed class DuplicateTypeNameRuleKotlin : DuplicateTypeNameRule
{
    public override string Key => "QG-KT-SML-0110";
    public override string[] Languages => ["kt"];
}

public sealed class DuplicateTypeNameRuleJs : DuplicateTypeNameRule
{
    public override string Key => "QG-JS-SML-0404";
    public override string[] Languages => ["js", "ts"];
}

public sealed class DuplicateTypeNameRulePython : DuplicateTypeNameRule
{
    public override string Key => "QG-PY-SML-0283";
    public override string[] Languages => ["py"];
}

public sealed class DuplicateTypeNameRulePhp : DuplicateTypeNameRule
{
    public override string Key => "QG-PP-SML-0148";
    public override string[] Languages => ["php"];
}

public sealed class DuplicateTypeNameRuleGo : DuplicateTypeNameRule
{
    public override string Key => "QG-GO-SML-0062";
    public override string[] Languages => ["go"];
}

public sealed class DuplicateTypeNameRuleDart : DuplicateTypeNameRule
{
    public override string Key => "QG-DART-SML-0027";
    public override string[] Languages => ["dart"];
}

public sealed class DuplicateTypeNameRuleRuby : DuplicateTypeNameRule
{
    public override string Key => "QG-RB-SML-0061";
    public override string[] Languages => ["rb"];
}

public sealed class DuplicateTypeNameRuleSwift : DuplicateTypeNameRule
{
    public override string Key => "QG-SW-SML-0045";
    public override string[] Languages => ["swift"];
}

public sealed class DuplicateTypeNameRuleCss : DuplicateTypeNameRule
{
    public override string Key => "QG-CSS-SML-0066";
    public override string[] Languages => ["css"];
}

public sealed class DuplicateTypeNameRuleHtml : DuplicateTypeNameRule
{
    public override string Key => "QG-HTML-SML-0138";
    public override string[] Languages => ["html"];
}

public sealed class DuplicateTypeNameRuleXml : DuplicateTypeNameRule
{
    public override string Key => "QG-XML-SML-0053";
    public override string[] Languages => ["xml"];
}

public sealed class DuplicateTypeNameRuleTerraform : DuplicateTypeNameRule
{
    public override string Key => "QG-TF-SML-0045";
    public override string[] Languages => ["tf"];
}

public sealed class DuplicateTypeNameRuleDockerfile : DuplicateTypeNameRule
{
    public override string Key => "QG-DK-SML-0059";
    public override string[] Languages => ["dk"];
}

public sealed class DuplicateTypeNameRuleKubernetes : DuplicateTypeNameRule
{
    public override string Key => "QG-K8-SML-0053";
    public override string[] Languages => ["k8"];
}

public sealed class DuplicateTypeNameRuleCloudFormation : DuplicateTypeNameRule
{
    public override string Key => "QG-CF-SML-0046";
    public override string[] Languages => ["cf"];
}

public sealed class DuplicateTypeNameRuleJson : DuplicateTypeNameRule
{
    public override string Key => "QG-JSON-SML-0041";
    public override string[] Languages => ["json"];
}

public abstract class EqualityContractRule : StructuralRuleBase
{
    public override string Name => "Equality and hashing should be overridden together";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "15min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            var members = type.OfKind(NodeKind.FunctionDeclaration)
                .Where(m => m.Ancestor(NodeKind.ClassDeclaration) == type)
                .Select(m => m.Text)
                .ToArray();
            var hasEquals = members.Any(m => m is "Equals" or "equals" or "__eq__");
            var hasHash = members.Any(m => m is "GetHashCode" or "hashCode" or "__hash__");
            if (hasEquals == hasHash)
                continue;
            var present = hasEquals ? "equality" : "hashing";
            var missing = hasEquals ? "hashing" : "equality";
            context.Report(type, $"'{type.Text}' overrides {present} but not {missing}; "
                                 + "hash-based collections then fail to find items that compare equal.");
        }
    }
}

public sealed class EqualityContractRuleCs : EqualityContractRule
{
    public override string Key => "QG-CS-BUG-0162";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class EqualityContractRuleJava : EqualityContractRule
{
    public override string Key => "QG-JV-BUG-0216";
    public override string[] Languages => ["java"];
}

public sealed class EqualityContractRuleKotlin : EqualityContractRule
{
    public override string Key => "QG-KT-BUG-0043";
    public override string[] Languages => ["kt"];
}

public sealed class EqualityContractRuleJs : EqualityContractRule
{
    public override string Key => "QG-JS-BUG-0160";
    public override string[] Languages => ["js", "ts"];
}

public sealed class EqualityContractRulePython : EqualityContractRule
{
    public override string Key => "QG-PY-BUG-0166";
    public override string[] Languages => ["py"];
}

public sealed class EqualityContractRulePhp : EqualityContractRule
{
    public override string Key => "QG-PP-BUG-0063";
    public override string[] Languages => ["php"];
}

public sealed class EqualityContractRuleGo : EqualityContractRule
{
    public override string Key => "QG-GO-BUG-0019";
    public override string[] Languages => ["go"];
}

public sealed class EqualityContractRuleDart : EqualityContractRule
{
    public override string Key => "QG-DART-BUG-0017";
    public override string[] Languages => ["dart"];
}

public sealed class EqualityContractRuleRuby : EqualityContractRule
{
    public override string Key => "QG-RB-BUG-0038";
    public override string[] Languages => ["rb"];
}

public sealed class EqualityContractRuleSwift : EqualityContractRule
{
    public override string Key => "QG-SW-BUG-0042";
    public override string[] Languages => ["swift"];
}

public sealed class EqualityContractRuleCss : EqualityContractRule
{
    public override string Key => "QG-CSS-BUG-0067";
    public override string[] Languages => ["css"];
}

public sealed class EqualityContractRuleHtml : EqualityContractRule
{
    public override string Key => "QG-HTML-BUG-0067";
    public override string[] Languages => ["html"];
}

public sealed class EqualityContractRuleXml : EqualityContractRule
{
    public override string Key => "QG-XML-BUG-0042";
    public override string[] Languages => ["xml"];
}

public sealed class EqualityContractRuleTerraform : EqualityContractRule
{
    public override string Key => "QG-TF-BUG-0037";
    public override string[] Languages => ["tf"];
}

public sealed class EqualityContractRuleDockerfile : EqualityContractRule
{
    public override string Key => "QG-DK-BUG-0044";
    public override string[] Languages => ["dk"];
}

public sealed class EqualityContractRuleKubernetes : EqualityContractRule
{
    public override string Key => "QG-K8-BUG-0037";
    public override string[] Languages => ["k8"];
}

public sealed class EqualityContractRuleCloudFormation : EqualityContractRule
{
    public override string Key => "QG-CF-BUG-0037";
    public override string[] Languages => ["cf"];
}

public sealed class EqualityContractRuleJson : EqualityContractRule
{
    public override string Key => "QG-JSON-BUG-0038";
    public override string[] Languages => ["json"];
}

public abstract class OverrideOnlyCallsBaseRule : StructuralRuleBase
{
    public override string Name => "Overrides should add something";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var member in context.Root.OfKind(NodeKind.FunctionDeclaration))
        {
            var isOverride = member.ChildrenOf(NodeKind.Modifier).Any(m => m.Text == "override")
                             || member.ChildrenOf(NodeKind.Attribute).Any(a => a.Text == "Override");
            if (!isOverride)
                continue;
            var body = SyntaxQuery.Body(member);
            if (body is not { Children.Count: 1 })
                continue;

            var only = body.Children[0];
            var call = only.OfKind(NodeKind.Invocation).FirstOrDefault();
            if (call == null)
                continue;
            var callee = SyntaxQuery.InvokedDottedName(call);
            if (!callee.StartsWith("base.", StringComparison.Ordinal)
                && !callee.StartsWith("super.", StringComparison.Ordinal))
                continue;
            if (SyntaxQuery.SimpleName(call.ChildAt(0)) != member.Text)
                continue;
            context.Report(member, $"'{member.Text}' only forwards to the base implementation, "
                                   + "so removing it changes nothing.");
        }
    }
}

public sealed class OverrideOnlyCallsBaseRuleCs : OverrideOnlyCallsBaseRule
{
    public override string Key => "QG-CS-SML-0528";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class OverrideOnlyCallsBaseRuleJava : OverrideOnlyCallsBaseRule
{
    public override string Key => "QG-JV-SML-0489";
    public override string[] Languages => ["java"];
}

public sealed class OverrideOnlyCallsBaseRuleKotlin : OverrideOnlyCallsBaseRule
{
    public override string Key => "QG-KT-SML-0111";
    public override string[] Languages => ["kt"];
}

public sealed class OverrideOnlyCallsBaseRuleJs : OverrideOnlyCallsBaseRule
{
    public override string Key => "QG-JS-SML-0405";
    public override string[] Languages => ["js", "ts"];
}

public sealed class OverrideOnlyCallsBaseRulePython : OverrideOnlyCallsBaseRule
{
    public override string Key => "QG-PY-SML-0284";
    public override string[] Languages => ["py"];
}

public sealed class OverrideOnlyCallsBaseRulePhp : OverrideOnlyCallsBaseRule
{
    public override string Key => "QG-PP-SML-0149";
    public override string[] Languages => ["php"];
}

public sealed class OverrideOnlyCallsBaseRuleGo : OverrideOnlyCallsBaseRule
{
    public override string Key => "QG-GO-SML-0063";
    public override string[] Languages => ["go"];
}

public sealed class OverrideOnlyCallsBaseRuleDart : OverrideOnlyCallsBaseRule
{
    public override string Key => "QG-DART-SML-0028";
    public override string[] Languages => ["dart"];
}

public sealed class OverrideOnlyCallsBaseRuleRuby : OverrideOnlyCallsBaseRule
{
    public override string Key => "QG-RB-SML-0062";
    public override string[] Languages => ["rb"];
}

public sealed class OverrideOnlyCallsBaseRuleSwift : OverrideOnlyCallsBaseRule
{
    public override string Key => "QG-SW-SML-0046";
    public override string[] Languages => ["swift"];
}

public sealed class OverrideOnlyCallsBaseRuleCss : OverrideOnlyCallsBaseRule
{
    public override string Key => "QG-CSS-SML-0067";
    public override string[] Languages => ["css"];
}

public sealed class OverrideOnlyCallsBaseRuleHtml : OverrideOnlyCallsBaseRule
{
    public override string Key => "QG-HTML-SML-0139";
    public override string[] Languages => ["html"];
}

public sealed class OverrideOnlyCallsBaseRuleXml : OverrideOnlyCallsBaseRule
{
    public override string Key => "QG-XML-SML-0054";
    public override string[] Languages => ["xml"];
}

public sealed class OverrideOnlyCallsBaseRuleTerraform : OverrideOnlyCallsBaseRule
{
    public override string Key => "QG-TF-SML-0046";
    public override string[] Languages => ["tf"];
}

public sealed class OverrideOnlyCallsBaseRuleDockerfile : OverrideOnlyCallsBaseRule
{
    public override string Key => "QG-DK-SML-0060";
    public override string[] Languages => ["dk"];
}

public sealed class OverrideOnlyCallsBaseRuleKubernetes : OverrideOnlyCallsBaseRule
{
    public override string Key => "QG-K8-SML-0054";
    public override string[] Languages => ["k8"];
}

public sealed class OverrideOnlyCallsBaseRuleCloudFormation : OverrideOnlyCallsBaseRule
{
    public override string Key => "QG-CF-SML-0047";
    public override string[] Languages => ["cf"];
}

public sealed class OverrideOnlyCallsBaseRuleJson : OverrideOnlyCallsBaseRule
{
    public override string Key => "QG-JSON-SML-0042";
    public override string[] Languages => ["json"];
}

public abstract class EmptyTypeRule : StructuralRuleBase
{
    public override string Name => "Types should declare something";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "15min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            var body = type.FirstChild(NodeKind.Block);
            if (body is not { Children.Count: 0 })
                continue;
            if (type.BaseCount(context) > 0)
                continue; // an empty subclass can be a deliberate marker or a specialised exception
            // An annotated class carries its behaviour in the annotation: a module, an entity or a
            // configuration is declared entirely by what is attached to it, and the empty body is
            // the point rather than an oversight.
            if (type.ChildrenOf(NodeKind.Attribute).Any())
                continue;
            context.Report(type, $"'{type.Text}' declares no members; "
                                 + "give it behaviour or remove it.");
        }
    }
}

public sealed class EmptyTypeRuleCs : EmptyTypeRule
{
    public override string Key => "QG-CS-SML-0529";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class EmptyTypeRuleJava : EmptyTypeRule
{
    public override string Key => "QG-JV-SML-0490";
    public override string[] Languages => ["java"];
}

public sealed class EmptyTypeRuleKotlin : EmptyTypeRule
{
    public override string Key => "QG-KT-SML-0112";
    public override string[] Languages => ["kt"];
}

public sealed class EmptyTypeRuleJs : EmptyTypeRule
{
    public override string Key => "QG-JS-SML-0406";
    public override string[] Languages => ["js", "ts"];
}

public sealed class EmptyTypeRulePython : EmptyTypeRule
{
    public override string Key => "QG-PY-SML-0285";
    public override string[] Languages => ["py"];
}

public sealed class EmptyTypeRulePhp : EmptyTypeRule
{
    public override string Key => "QG-PP-SML-0150";
    public override string[] Languages => ["php"];
}

public sealed class EmptyTypeRuleGo : EmptyTypeRule
{
    public override string Key => "QG-GO-SML-0064";
    public override string[] Languages => ["go"];
}

public sealed class EmptyTypeRuleDart : EmptyTypeRule
{
    public override string Key => "QG-DART-SML-0029";
    public override string[] Languages => ["dart"];
}

public sealed class EmptyTypeRuleRuby : EmptyTypeRule
{
    public override string Key => "QG-RB-SML-0063";
    public override string[] Languages => ["rb"];
}

public sealed class EmptyTypeRuleSwift : EmptyTypeRule
{
    public override string Key => "QG-SW-SML-0047";
    public override string[] Languages => ["swift"];
}

public sealed class EmptyTypeRuleCss : EmptyTypeRule
{
    public override string Key => "QG-CSS-SML-0068";
    public override string[] Languages => ["css"];
}

public sealed class EmptyTypeRuleHtml : EmptyTypeRule
{
    public override string Key => "QG-HTML-SML-0140";
    public override string[] Languages => ["html"];
}

public sealed class EmptyTypeRuleXml : EmptyTypeRule
{
    public override string Key => "QG-XML-SML-0055";
    public override string[] Languages => ["xml"];
}

public sealed class EmptyTypeRuleTerraform : EmptyTypeRule
{
    public override string Key => "QG-TF-SML-0047";
    public override string[] Languages => ["tf"];
}

public sealed class EmptyTypeRuleDockerfile : EmptyTypeRule
{
    public override string Key => "QG-DK-SML-0061";
    public override string[] Languages => ["dk"];
}

public sealed class EmptyTypeRuleKubernetes : EmptyTypeRule
{
    public override string Key => "QG-K8-SML-0055";
    public override string[] Languages => ["k8"];
}

public sealed class EmptyTypeRuleCloudFormation : EmptyTypeRule
{
    public override string Key => "QG-CF-SML-0048";
    public override string[] Languages => ["cf"];
}

public sealed class EmptyTypeRuleJson : EmptyTypeRule
{
    public override string Key => "QG-JSON-SML-0043";
    public override string[] Languages => ["json"];
}

internal static class TypeNodeExtensions
{
    /// <summary>Number of base types the declaration names, as seen by the project index.</summary>
    public static int BaseCount(this SyntaxNode type, IRuleContext context)
        => context.Project.FindTypes(type.Text).FirstOrDefault(t => t.Node == type)?.BaseNames.Count ?? 0;
}

public abstract class FieldCouldBeReadOnlyRule : StructuralRuleBase
{
    public override string Name => "Fields set only during construction should be read-only";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context) || context.Language.LanguageKey is not ("cs" or "java" or "kt"))
            return;

        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            foreach (var field in type.OfKind(NodeKind.FieldDeclaration))
            {
                if (field.Ancestor(NodeKind.ClassDeclaration) != type || field.Text.Length == 0)
                    continue;
                var modifiers = field.ChildrenOf(NodeKind.Modifier).Select(m => m.Text).ToArray();
                // 'val' is how Kotlin and Scala spell it, and 'let' is Swift's: a declaration that
                // already cannot be reassigned was being told to become read-only, four hundred and
                // fifty times on one project.
                if (modifiers.Any(m => m is "readonly" or "const" or "final" or "static" or "volatile"
                        or "val" or "let")
                    || field.Text is "val" or "let"
                    || field.Tokens.Any(t => t.Text is "val" or "let"))
                    continue;
                if (!modifiers.Contains("private"))
                    continue;

                var assignments = type.OfKind(NodeKind.Assignment)
                    .Where(a => SyntaxQuery.SimpleName(a.ChildAt(0)) == field.Text)
                    .ToList();
                if (assignments.Count == 0)
                    continue;

                var outsideConstruction = assignments.Any(a =>
                    a.Ancestor(NodeKind.ConstructorDeclaration) == null
                    && a.Ancestor(NodeKind.FieldDeclaration) == null);
                if (outsideConstruction)
                    continue;

                context.Report(field, $"'{field.Text}' never changes after construction; "
                                      + "mark it read-only so the compiler enforces that.");
            }
        }
    }
}

public sealed class FieldCouldBeReadOnlyRuleCs : FieldCouldBeReadOnlyRule
{
    public override string Key => "QG-CS-SML-0530";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class FieldCouldBeReadOnlyRuleJava : FieldCouldBeReadOnlyRule
{
    public override string Key => "QG-JV-SML-0491";
    public override string[] Languages => ["java"];
}

public sealed class FieldCouldBeReadOnlyRuleKotlin : FieldCouldBeReadOnlyRule
{
    public override string Key => "QG-KT-SML-0113";
    public override string[] Languages => ["kt"];
}

public sealed class FieldCouldBeReadOnlyRuleJs : FieldCouldBeReadOnlyRule
{
    public override string Key => "QG-JS-SML-0407";
    public override string[] Languages => ["js", "ts"];
}

public sealed class FieldCouldBeReadOnlyRulePython : FieldCouldBeReadOnlyRule
{
    public override string Key => "QG-PY-SML-0286";
    public override string[] Languages => ["py"];
}

public sealed class FieldCouldBeReadOnlyRulePhp : FieldCouldBeReadOnlyRule
{
    public override string Key => "QG-PP-SML-0151";
    public override string[] Languages => ["php"];
}

public sealed class FieldCouldBeReadOnlyRuleGo : FieldCouldBeReadOnlyRule
{
    public override string Key => "QG-GO-SML-0065";
    public override string[] Languages => ["go"];
}

public sealed class FieldCouldBeReadOnlyRuleDart : FieldCouldBeReadOnlyRule
{
    public override string Key => "QG-DART-SML-0030";
    public override string[] Languages => ["dart"];
}

public sealed class FieldCouldBeReadOnlyRuleRuby : FieldCouldBeReadOnlyRule
{
    public override string Key => "QG-RB-SML-0064";
    public override string[] Languages => ["rb"];
}

public sealed class FieldCouldBeReadOnlyRuleSwift : FieldCouldBeReadOnlyRule
{
    public override string Key => "QG-SW-SML-0048";
    public override string[] Languages => ["swift"];
}

public sealed class FieldCouldBeReadOnlyRuleCss : FieldCouldBeReadOnlyRule
{
    public override string Key => "QG-CSS-SML-0069";
    public override string[] Languages => ["css"];
}

public sealed class FieldCouldBeReadOnlyRuleHtml : FieldCouldBeReadOnlyRule
{
    public override string Key => "QG-HTML-SML-0141";
    public override string[] Languages => ["html"];
}

public sealed class FieldCouldBeReadOnlyRuleXml : FieldCouldBeReadOnlyRule
{
    public override string Key => "QG-XML-SML-0056";
    public override string[] Languages => ["xml"];
}

public sealed class FieldCouldBeReadOnlyRuleTerraform : FieldCouldBeReadOnlyRule
{
    public override string Key => "QG-TF-SML-0048";
    public override string[] Languages => ["tf"];
}

public sealed class FieldCouldBeReadOnlyRuleDockerfile : FieldCouldBeReadOnlyRule
{
    public override string Key => "QG-DK-SML-0062";
    public override string[] Languages => ["dk"];
}

public sealed class FieldCouldBeReadOnlyRuleKubernetes : FieldCouldBeReadOnlyRule
{
    public override string Key => "QG-K8-SML-0056";
    public override string[] Languages => ["k8"];
}

public sealed class FieldCouldBeReadOnlyRuleCloudFormation : FieldCouldBeReadOnlyRule
{
    public override string Key => "QG-CF-SML-0049";
    public override string[] Languages => ["cf"];
}

public sealed class FieldCouldBeReadOnlyRuleJson : FieldCouldBeReadOnlyRule
{
    public override string Key => "QG-JSON-SML-0044";
    public override string[] Languages => ["json"];
}

public abstract class MethodCouldBeStaticRule : StructuralRuleBase
{
    public override string Name => "Members that ignore instance state should be static";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context) || context.Language.LanguageKey is not ("cs" or "java"))
            return;

        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            var instanceMembers = type
                .OfKind(NodeKind.FieldDeclaration, NodeKind.PropertyDeclaration, NodeKind.FunctionDeclaration)
                .Where(m => m.Ancestor(NodeKind.ClassDeclaration) == type
                            && !m.ChildrenOf(NodeKind.Modifier).Any(x => x.Text == "static"))
                .Select(m => m.Text)
                .Where(name => name.Length > 0)
                .ToHashSet(StringComparer.Ordinal);

            foreach (var method in type.OfKind(NodeKind.FunctionDeclaration))
            {
                if (method.Ancestor(NodeKind.ClassDeclaration) != type || method.Text.Length == 0)
                    continue;
                var modifiers = method.ChildrenOf(NodeKind.Modifier).Select(m => m.Text).ToArray();
                if (modifiers.Any(m => m is "static" or "override" or "virtual" or "abstract" or "partial"
                        or "default" or "extern" or "async"))
                    continue;
                // Only a private method can be turned static without touching anything outside the
                // class: everything else is somebody's contract — an override, an implementation of
                // an interface, or a member a subclass is expected to be able to replace. The engine
                // cannot see those callers from one file, so it does not guess about them.
                if (!modifiers.Contains("private", StringComparer.Ordinal))
                    continue;
                if (method.ChildrenOf(NodeKind.Attribute).Any() || method.ChildrenOf(NodeKind.Annotation).Any())
                    continue; // a framework may require the instance form
                var body = SyntaxQuery.Body(method);
                if (body is null or { Children.Count: 0 })
                    continue;

                var touchesInstance = body.OfKind(NodeKind.Identifier)
                    .Any(i => i.Text is "this" or "base" or "super" || instanceMembers.Contains(i.Text))
                    || body.OfKind(NodeKind.Invocation)
                        .Any(call => instanceMembers.Contains(SyntaxQuery.InvokedName(call)));
                if (touchesInstance)
                    continue;

                context.Report(method, $"'{method.Text}' never reads the instance; "
                                       + "make it static so callers do not need an object.");
            }
        }
    }
}

public sealed class MethodCouldBeStaticRuleCs : MethodCouldBeStaticRule
{
    public override string Key => "QG-CS-SML-0531";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class MethodCouldBeStaticRuleJava : MethodCouldBeStaticRule
{
    public override string Key => "QG-JV-SML-0492";
    public override string[] Languages => ["java"];
}

public sealed class MethodCouldBeStaticRuleKotlin : MethodCouldBeStaticRule
{
    public override string Key => "QG-KT-SML-0114";
    public override string[] Languages => ["kt"];
}

public sealed class MethodCouldBeStaticRuleJs : MethodCouldBeStaticRule
{
    public override string Key => "QG-JS-SML-0408";
    public override string[] Languages => ["js", "ts"];
}

public sealed class MethodCouldBeStaticRulePython : MethodCouldBeStaticRule
{
    public override string Key => "QG-PY-SML-0287";
    public override string[] Languages => ["py"];
}

public sealed class MethodCouldBeStaticRulePhp : MethodCouldBeStaticRule
{
    public override string Key => "QG-PP-SML-0152";
    public override string[] Languages => ["php"];
}

public sealed class MethodCouldBeStaticRuleGo : MethodCouldBeStaticRule
{
    public override string Key => "QG-GO-SML-0066";
    public override string[] Languages => ["go"];
}

public sealed class MethodCouldBeStaticRuleDart : MethodCouldBeStaticRule
{
    public override string Key => "QG-DART-SML-0031";
    public override string[] Languages => ["dart"];
}

public sealed class MethodCouldBeStaticRuleRuby : MethodCouldBeStaticRule
{
    public override string Key => "QG-RB-SML-0065";
    public override string[] Languages => ["rb"];
}

public sealed class MethodCouldBeStaticRuleSwift : MethodCouldBeStaticRule
{
    public override string Key => "QG-SW-SML-0049";
    public override string[] Languages => ["swift"];
}

public sealed class MethodCouldBeStaticRuleCss : MethodCouldBeStaticRule
{
    public override string Key => "QG-CSS-SML-0070";
    public override string[] Languages => ["css"];
}

public sealed class MethodCouldBeStaticRuleHtml : MethodCouldBeStaticRule
{
    public override string Key => "QG-HTML-SML-0142";
    public override string[] Languages => ["html"];
}

public sealed class MethodCouldBeStaticRuleXml : MethodCouldBeStaticRule
{
    public override string Key => "QG-XML-SML-0057";
    public override string[] Languages => ["xml"];
}

public sealed class MethodCouldBeStaticRuleTerraform : MethodCouldBeStaticRule
{
    public override string Key => "QG-TF-SML-0049";
    public override string[] Languages => ["tf"];
}

public sealed class MethodCouldBeStaticRuleDockerfile : MethodCouldBeStaticRule
{
    public override string Key => "QG-DK-SML-0063";
    public override string[] Languages => ["dk"];
}

public sealed class MethodCouldBeStaticRuleKubernetes : MethodCouldBeStaticRule
{
    public override string Key => "QG-K8-SML-0057";
    public override string[] Languages => ["k8"];
}

public sealed class MethodCouldBeStaticRuleCloudFormation : MethodCouldBeStaticRule
{
    public override string Key => "QG-CF-SML-0050";
    public override string[] Languages => ["cf"];
}

public sealed class MethodCouldBeStaticRuleJson : MethodCouldBeStaticRule
{
    public override string Key => "QG-JSON-SML-0045";
    public override string[] Languages => ["json"];
}

public abstract class MutableStaticStateRule : StructuralRuleBase
{
    public override string Name => "Shared state should not be mutable";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "20min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var field in context.Root.OfKind(NodeKind.FieldDeclaration))
        {
            var modifiers = field.ChildrenOf(NodeKind.Modifier).Select(m => m.Text).ToArray();
            if (!modifiers.Contains("static") || modifiers.Any(m => m is "readonly" or "const" or "final"))
                continue;
            if (modifiers.Contains("private"))
                continue;
            context.Report(field, $"'{field.Text}' is shared by the whole process and can be replaced by "
                                  + "any caller, from any thread; make it read-only or move it behind a "
                                  + "scoped service.");
        }
    }
}

public sealed class MutableStaticStateRuleCs : MutableStaticStateRule
{
    public override string Key => "QG-CS-SML-0532";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class MutableStaticStateRuleJava : MutableStaticStateRule
{
    public override string Key => "QG-JV-SML-0493";
    public override string[] Languages => ["java"];
}

public sealed class MutableStaticStateRuleKotlin : MutableStaticStateRule
{
    public override string Key => "QG-KT-SML-0115";
    public override string[] Languages => ["kt"];
}

public sealed class MutableStaticStateRuleJs : MutableStaticStateRule
{
    public override string Key => "QG-JS-SML-0409";
    public override string[] Languages => ["js", "ts"];
}

public sealed class MutableStaticStateRulePython : MutableStaticStateRule
{
    public override string Key => "QG-PY-SML-0288";
    public override string[] Languages => ["py"];
}

public sealed class MutableStaticStateRulePhp : MutableStaticStateRule
{
    public override string Key => "QG-PP-SML-0153";
    public override string[] Languages => ["php"];
}

public sealed class MutableStaticStateRuleGo : MutableStaticStateRule
{
    public override string Key => "QG-GO-SML-0067";
    public override string[] Languages => ["go"];
}

public sealed class MutableStaticStateRuleDart : MutableStaticStateRule
{
    public override string Key => "QG-DART-SML-0032";
    public override string[] Languages => ["dart"];
}

public sealed class MutableStaticStateRuleRuby : MutableStaticStateRule
{
    public override string Key => "QG-RB-SML-0066";
    public override string[] Languages => ["rb"];
}

public sealed class MutableStaticStateRuleSwift : MutableStaticStateRule
{
    public override string Key => "QG-SW-SML-0050";
    public override string[] Languages => ["swift"];
}

public sealed class MutableStaticStateRuleCss : MutableStaticStateRule
{
    public override string Key => "QG-CSS-SML-0071";
    public override string[] Languages => ["css"];
}

public sealed class MutableStaticStateRuleHtml : MutableStaticStateRule
{
    public override string Key => "QG-HTML-SML-0143";
    public override string[] Languages => ["html"];
}

public sealed class MutableStaticStateRuleXml : MutableStaticStateRule
{
    public override string Key => "QG-XML-SML-0058";
    public override string[] Languages => ["xml"];
}

public sealed class MutableStaticStateRuleTerraform : MutableStaticStateRule
{
    public override string Key => "QG-TF-SML-0050";
    public override string[] Languages => ["tf"];
}

public sealed class MutableStaticStateRuleDockerfile : MutableStaticStateRule
{
    public override string Key => "QG-DK-SML-0064";
    public override string[] Languages => ["dk"];
}

public sealed class MutableStaticStateRuleKubernetes : MutableStaticStateRule
{
    public override string Key => "QG-K8-SML-0058";
    public override string[] Languages => ["k8"];
}

public sealed class MutableStaticStateRuleCloudFormation : MutableStaticStateRule
{
    public override string Key => "QG-CF-SML-0051";
    public override string[] Languages => ["cf"];
}

public sealed class MutableStaticStateRuleJson : MutableStaticStateRule
{
    public override string Key => "QG-JSON-SML-0046";
    public override string[] Languages => ["json"];
}

public abstract class UnreleasedResourceRule : StructuralRuleBase
{
    private static readonly string[] ResourceTypes =
    [
        "FileStream", "StreamReader", "StreamWriter", "SqlConnection", "SqlCommand", "HttpClient",
        "MemoryStream", "Socket", "TcpClient", "NpgsqlConnection", "MySqlConnection", "FileInputStream",
        "FileOutputStream", "FileReader", "FileWriter", "BufferedReader", "ServerSocket", "Scanner"
    ];

    private static readonly string[] ReleaseNames = ["Dispose", "close", "Close", "DisposeAsync"];
    public override string Name => "Resources should be released on every path";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "20min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context) || context.Language.LanguageKey is not ("cs" or "java" or "kt"))
            return;

        foreach (var declaration in context.Root.OfKind(NodeKind.VariableDeclaration))
        {
            var creation = declaration.OfKind(NodeKind.ObjectCreation).FirstOrDefault();
            if (creation == null)
                continue;
            var type = Semantics.TypeResolver.Normalize(creation.Text);
            if (!ResourceTypes.Contains(type, StringComparer.Ordinal))
                continue;
            if (declaration.Ancestor(NodeKind.Using) != null || declaration.Kind == NodeKind.Using)
                continue;
            if (declaration.Parent?.Kind == NodeKind.Using)
                continue;

            var function = SyntaxQuery.EnclosingFunction(declaration);
            var released = function != null && function.OfKind(NodeKind.Invocation)
                .Any(call => ReleaseNames.Contains(SyntaxQuery.InvokedName(call), StringComparer.Ordinal)
                             && SyntaxQuery.Receiver(call) == declaration.Text);
            if (released)
                continue;

            context.Report(declaration, $"'{declaration.Text}' holds a {type} that is never released; "
                                        + "declare it in a using or try-with-resources block so it closes "
                                        + "on every path, including the exceptional ones.");
        }
    }
}

public sealed class UnreleasedResourceRuleCs : UnreleasedResourceRule
{
    public override string Key => "QG-CS-BUG-0163";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class UnreleasedResourceRuleJava : UnreleasedResourceRule
{
    public override string Key => "QG-JV-BUG-0217";
    public override string[] Languages => ["java"];
}

public sealed class UnreleasedResourceRuleKotlin : UnreleasedResourceRule
{
    public override string Key => "QG-KT-BUG-0044";
    public override string[] Languages => ["kt"];
}

public sealed class UnreleasedResourceRuleJs : UnreleasedResourceRule
{
    public override string Key => "QG-JS-BUG-0161";
    public override string[] Languages => ["js", "ts"];
}

public sealed class UnreleasedResourceRulePython : UnreleasedResourceRule
{
    public override string Key => "QG-PY-BUG-0167";
    public override string[] Languages => ["py"];
}

public sealed class UnreleasedResourceRulePhp : UnreleasedResourceRule
{
    public override string Key => "QG-PP-BUG-0064";
    public override string[] Languages => ["php"];
}

public sealed class UnreleasedResourceRuleGo : UnreleasedResourceRule
{
    public override string Key => "QG-GO-BUG-0020";
    public override string[] Languages => ["go"];
}

public sealed class UnreleasedResourceRuleDart : UnreleasedResourceRule
{
    public override string Key => "QG-DART-BUG-0018";
    public override string[] Languages => ["dart"];
}

public sealed class UnreleasedResourceRuleRuby : UnreleasedResourceRule
{
    public override string Key => "QG-RB-BUG-0039";
    public override string[] Languages => ["rb"];
}

public sealed class UnreleasedResourceRuleSwift : UnreleasedResourceRule
{
    public override string Key => "QG-SW-BUG-0043";
    public override string[] Languages => ["swift"];
}

public sealed class UnreleasedResourceRuleCss : UnreleasedResourceRule
{
    public override string Key => "QG-CSS-BUG-0068";
    public override string[] Languages => ["css"];
}

public sealed class UnreleasedResourceRuleHtml : UnreleasedResourceRule
{
    public override string Key => "QG-HTML-BUG-0068";
    public override string[] Languages => ["html"];
}

public sealed class UnreleasedResourceRuleXml : UnreleasedResourceRule
{
    public override string Key => "QG-XML-BUG-0043";
    public override string[] Languages => ["xml"];
}

public sealed class UnreleasedResourceRuleTerraform : UnreleasedResourceRule
{
    public override string Key => "QG-TF-BUG-0038";
    public override string[] Languages => ["tf"];
}

public sealed class UnreleasedResourceRuleDockerfile : UnreleasedResourceRule
{
    public override string Key => "QG-DK-BUG-0045";
    public override string[] Languages => ["dk"];
}

public sealed class UnreleasedResourceRuleKubernetes : UnreleasedResourceRule
{
    public override string Key => "QG-K8-BUG-0038";
    public override string[] Languages => ["k8"];
}

public sealed class UnreleasedResourceRuleCloudFormation : UnreleasedResourceRule
{
    public override string Key => "QG-CF-BUG-0038";
    public override string[] Languages => ["cf"];
}

public sealed class UnreleasedResourceRuleJson : UnreleasedResourceRule
{
    public override string Key => "QG-JSON-BUG-0039";
    public override string[] Languages => ["json"];
}

public abstract class MismatchedComparisonRule : StructuralRuleBase
{
    private static readonly string[] Numeric =
        ["int", "long", "short", "byte", "double", "float", "decimal", "number", "Integer", "Double"];

    private static readonly string[] Primitive =
        ["int", "long", "short", "byte", "double", "float", "decimal", "number", "bool", "boolean",
         "string", "str", "char", "object"];
    public override string Name => "Values of unrelated types should not be compared";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "15min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var comparison in context.Root.OfKind(NodeKind.Binary))
        {
            if (comparison.Text is not ("==" or "!=" or "===" or "!=="))
                continue;
            var left = context.Types.TypeOf(comparison.ChildAt(0));
            var right = context.Types.TypeOf(comparison.ChildAt(1));
            if (left == null || right == null || left == right)
                continue;
            // only compare names that are really types: anything else is an expression the resolver
            // could not follow, and two unknowns never prove that a comparison is impossible
            if (!context.Types.IsKnownType(left) || !context.Types.IsKnownType(right))
                continue;
            if (Numeric.Contains(left, StringComparer.Ordinal) && Numeric.Contains(right, StringComparer.Ordinal))
                continue;
            // TypeScript names a union of literals with `type X = 'a' | 'b'`, which the index sees as
            // a declaration with no shape. Comparing such a name with a primitive proves nothing, so
            // the pair is only reported where a named type cannot be an alias for a primitive.
            if (context.Language.LanguageKey is "ts" or "js"
                && (Primitive.Contains(left, StringComparer.Ordinal)
                    || Primitive.Contains(right, StringComparer.Ordinal)))
                continue;
            if (context.Types.IsOrDerivesFrom(left, right) || context.Types.IsOrDerivesFrom(right, left))
                continue;
            context.Report(comparison, $"A value of type {left} can never equal one of type {right}, "
                                       + "so this comparison is constant.");
        }
    }
}

public sealed class MismatchedComparisonRuleCs : MismatchedComparisonRule
{
    public override string Key => "QG-CS-BUG-0164";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class MismatchedComparisonRuleJava : MismatchedComparisonRule
{
    public override string Key => "QG-JV-BUG-0218";
    public override string[] Languages => ["java"];
}

public sealed class MismatchedComparisonRuleKotlin : MismatchedComparisonRule
{
    public override string Key => "QG-KT-BUG-0045";
    public override string[] Languages => ["kt"];
}

public sealed class MismatchedComparisonRuleJs : MismatchedComparisonRule
{
    public override string Key => "QG-JS-BUG-0162";
    public override string[] Languages => ["js", "ts"];
}

public sealed class MismatchedComparisonRulePython : MismatchedComparisonRule
{
    public override string Key => "QG-PY-BUG-0168";
    public override string[] Languages => ["py"];
}

public sealed class MismatchedComparisonRulePhp : MismatchedComparisonRule
{
    public override string Key => "QG-PP-BUG-0065";
    public override string[] Languages => ["php"];
}

public sealed class MismatchedComparisonRuleGo : MismatchedComparisonRule
{
    public override string Key => "QG-GO-BUG-0021";
    public override string[] Languages => ["go"];
}

public sealed class MismatchedComparisonRuleDart : MismatchedComparisonRule
{
    public override string Key => "QG-DART-BUG-0019";
    public override string[] Languages => ["dart"];
}

public sealed class MismatchedComparisonRuleRuby : MismatchedComparisonRule
{
    public override string Key => "QG-RB-BUG-0040";
    public override string[] Languages => ["rb"];
}

public sealed class MismatchedComparisonRuleSwift : MismatchedComparisonRule
{
    public override string Key => "QG-SW-BUG-0044";
    public override string[] Languages => ["swift"];
}

public sealed class MismatchedComparisonRuleCss : MismatchedComparisonRule
{
    public override string Key => "QG-CSS-BUG-0069";
    public override string[] Languages => ["css"];
}

public sealed class MismatchedComparisonRuleHtml : MismatchedComparisonRule
{
    public override string Key => "QG-HTML-BUG-0069";
    public override string[] Languages => ["html"];
}

public sealed class MismatchedComparisonRuleXml : MismatchedComparisonRule
{
    public override string Key => "QG-XML-BUG-0044";
    public override string[] Languages => ["xml"];
}

public sealed class MismatchedComparisonRuleTerraform : MismatchedComparisonRule
{
    public override string Key => "QG-TF-BUG-0039";
    public override string[] Languages => ["tf"];
}

public sealed class MismatchedComparisonRuleDockerfile : MismatchedComparisonRule
{
    public override string Key => "QG-DK-BUG-0046";
    public override string[] Languages => ["dk"];
}

public sealed class MismatchedComparisonRuleKubernetes : MismatchedComparisonRule
{
    public override string Key => "QG-K8-BUG-0039";
    public override string[] Languages => ["k8"];
}

public sealed class MismatchedComparisonRuleCloudFormation : MismatchedComparisonRule
{
    public override string Key => "QG-CF-BUG-0039";
    public override string[] Languages => ["cf"];
}

public sealed class MismatchedComparisonRuleJson : MismatchedComparisonRule
{
    public override string Key => "QG-JSON-BUG-0040";
    public override string[] Languages => ["json"];
}
