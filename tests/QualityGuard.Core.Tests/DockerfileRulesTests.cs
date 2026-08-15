using Xunit;

namespace QualityGuard.Core.Tests;

/// <summary>Dockerfile rules: the defect, and the correct instruction next to it.</summary>
public class DockerfileRulesTests
{
    private static IReadOnlyList<int> Lines(string content, string rule)
        => Analyze.LinesOf(Analyze.WithRules("Dockerfile", content, rule), rule);

    [Fact]
    public void A_lower_case_instruction_is_reported()
    {
        var file = """
            FROM alpine:3.19
            run apk add curl
            """;
        Assert.Equal([2], Lines(file, "QG-DK-CNV-0002"));
    }

    [Fact]
    public void A_relative_workdir_is_reported_and_an_absolute_one_is_not()
    {
        var file = """
            FROM alpine:3.19
            WORKDIR app
            WORKDIR /srv/app
            """;
        Assert.Equal([2], Lines(file, "QG-DK-BUG-0005"));
    }

    [Fact]
    public void A_second_cmd_in_the_same_stage_is_reported()
    {
        var file = """
            FROM alpine:3.19
            CMD ["one"]
            CMD ["two"]
            """;
        Assert.Equal([3], Lines(file, "QG-DK-BUG-0006"));
    }

    [Fact]
    public void One_cmd_per_stage_is_left_alone()
    {
        var file = """
            FROM alpine:3.19 AS build
            CMD ["build"]

            FROM alpine:3.19
            CMD ["run"]
            """;
        Assert.Empty(Lines(file, "QG-DK-BUG-0006"));
    }

    [Fact]
    public void Add_of_a_local_file_is_reported_but_an_archive_or_a_url_is_not()
    {
        var file = """
            FROM alpine:3.19
            ADD app.jar /srv/app.jar
            ADD release.tar.gz /srv/
            ADD https://example.com/tool /usr/bin/tool
            """;
        Assert.Equal([2], Lines(file, "QG-DK-SML-0017"));
    }

    [Fact]
    public void Copying_the_whole_context_is_reported()
    {
        var file = """
            FROM alpine:3.19
            COPY . /srv/app
            COPY src/ /srv/app/src
            """;
        Assert.Equal([2], Lines(file, "QG-DK-SEC-0019"));
    }

    [Fact]
    public void A_space_around_the_equal_sign_is_reported()
    {
        var file = """
            FROM alpine:3.19
            ENV PORT = 8080
            ARG VERSION=1.2.3
            """;
        Assert.Equal([2], Lines(file, "QG-DK-BUG-0007"));
    }

    [Fact]
    public void Three_consecutive_run_instructions_are_reported()
    {
        var file = """
            FROM alpine:3.19
            RUN apk update
            RUN apk add curl
            RUN rm -rf /var/cache/apk
            """;
        Assert.NotEmpty(Lines(file, "QG-DK-SML-0018"));
    }

    [Fact]
    public void Two_run_instructions_are_left_alone()
    {
        var file = """
            FROM alpine:3.19
            RUN apk update
            RUN apk add curl
            """;
        Assert.Empty(Lines(file, "QG-DK-SML-0018"));
    }
}
