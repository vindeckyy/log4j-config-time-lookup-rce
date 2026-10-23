package lab;

import org.apache.logging.log4j.ThreadContext;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.core.lookup.StrSubstitutor;

/** Isolates the substitution engine: which lookup results get re-evaluated? */
public final class SubstProbe {

    public static void main(final String[] args) {
        final LoggerContext ctx = LoggerContext.getContext(false);
        final Configuration config = ctx.getConfiguration();
        final StrSubstitutor sub = config.getStrSubstitutor();

        ThreadContext.put("ua", "V=${env:HOME}");
        System.out.println("replace(\"${ctx:ua}\")            = " + sub.replace("${ctx:ua}"));
        System.out.println("replace(\"x ${ctx:ua} y\")        = " + sub.replace("x ${ctx:ua} y"));
        System.out.println("replace(\"${env:HOME}\")           = " + sub.replace("${env:HOME}"));
        System.out.println("replace(\"${sys:user.name}\")      = " + sub.replace("${sys:user.name}"));
        System.out.println("replace(\"${event:Message}\")      = " + sub.replace("${event:Message}"));
        System.out.println("replace(\"${ctx:ua}\") after ctx  = " + sub.replace("${ctx:ua}"));
        ThreadContext.clearMap();
    }

    private SubstProbe() {}
}
