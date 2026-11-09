/* Unit test for the supervisor's line grammar (GEN-03/04). Built natively by test-records.sh. */
#define main supervisor_main
#include "05-supervisor.c"
#undef main

static int failures;
static void t(const char *agent, const char *line, enum line_class want) {
    if (classify_line(agent, line) != want) { printf("FAIL: [%s] %s\n", agent, line); failures++; }
}

int main(void) {
    const char *d = "doc_agent";
    t(d, "HELLO doc_agent", LINE_BENIGN);
    t(d, "ALLOW doc_agent write /tmp/doc/x", LINE_BENIGN);
    t(d, "TRY doc_agent probe ok x", LINE_BENIGN);
    t(d, "DONE doc_agent", LINE_BENIGN);
    t(d, "DENY doc_agent write /tmp/x errno=13", LINE_DENIAL);
    t(d, "ERROR doc_agent sandbox failed", LINE_DENIAL);
    t(d, "ALLOW DENY doc_agent execve", LINE_INVALID);      /* a benign word in front */
    t(d, "ALLOW shell_agent write x", LINE_INVALID);        /* the other agent's name */
    t(d, "ALLOW doc_agentX write x", LINE_INVALID);         /* a longer name */
    t(d, "HALT supervisor", LINE_INVALID);
    t(d, "DONE supervisor", LINE_INVALID);
    t(d, "LSM landlock", LINE_INVALID);
    t(d, "ALLOW", LINE_INVALID);
    t(d, "", LINE_INVALID);
    t(d, "ALLOW doc_agent \x1b[2J", LINE_INVALID);          /* control bytes */
    t(d, "ALLOW doc_agent \xc3\xa9", LINE_INVALID);         /* non-ASCII */
    printf("line grammar: %s\n", failures ? "FAIL" : "PASS");
    return failures != 0;
}
