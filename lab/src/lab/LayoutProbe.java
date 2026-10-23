package lab;

import java.util.Collections;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.core.impl.Log4jLogEvent;
import org.apache.logging.log4j.core.layout.PatternLayout;
import org.apache.logging.log4j.core.lookup.StrSubstitutor;
import org.apache.logging.log4j.message.SimpleMessage;
import org.apache.logging.log4j.util.SortedArrayStringMap;

/** Where exactly does the MDC value get re-evaluated? */
public final class LayoutProbe {

    public static void main(final String[] args) {
        final LoggerContext ctx = LoggerContext.getContext(false);
        final Configuration config = ctx.getConfiguration();
        final StrSubstitutor configSub = config.getStrSubstitutor();

        final Log4jLogEvent event = Log4jLogEvent.newBuilder()
                .setLoggerName("probe")
                .setLevel(Level.INFO)
                .setMessage(new SimpleMessage("hello"))
                .setContextData(new SortedArrayStringMap(Collections.singletonMap("ua", "V=${env:HOME}")))
                .build();

        System.out.println("event ctx value            = " + event.getContextData().getValue("ua"));
        System.out.println("configSub.replace(event)   = " + configSub.replace(event, "${ctx:ua}"));
        System.out.println("configSub.replace(noevent) = " + configSub.replace("${ctx:ua}"));

        final PatternLayout layout =
                PatternLayout.newBuilder().withPattern("CTX=${ctx:ua}").build();
        System.out.println("PatternLayout output       = " + layout.toSerializable(event).trim());
    }

    private LayoutProbe() {}
}
