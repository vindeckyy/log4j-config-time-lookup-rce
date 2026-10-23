package lab;

import java.util.Collections;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.core.impl.Log4jLogEvent;
import org.apache.logging.log4j.core.lookup.StrSubstitutor;
import org.apache.logging.log4j.message.SimpleMessage;
import org.apache.logging.log4j.util.SortedArrayStringMap;

/** With a real (XML) configuration: which substitutor recurses, and which does the layout use? */
public final class LayoutProbe2 {

    public static void main(final String[] args) {
        final LoggerContext ctx = LoggerContext.getContext(false);
        final Configuration config = ctx.getConfiguration();
        System.out.println("configuration class = " + config.getClass().getName());
        final StrSubstitutor runtime = config.getStrSubstitutor();
        final StrSubstitutor configuration = config.getConfigurationStrSubstitutor();
        System.out.println("runtime substitutor class      = " + runtime.getClass().getName());
        System.out.println("configuration substitutor class = " + configuration.getClass().getName());

        final Log4jLogEvent event = Log4jLogEvent.newBuilder()
                .setLoggerName("probe")
                .setLevel(Level.INFO)
                .setMessage(new SimpleMessage("hello"))
                .setContextData(new SortedArrayStringMap(Collections.singletonMap("ua", "V=${env:HOME}")))
                .build();

        System.out.println("runtime.replace(event, ctx)      = " + runtime.replace(event, "${ctx:ua}"));
        System.out.println("configuration.replace(event,ctx) = " + configuration.replace(event, "${ctx:ua}"));
    }

    private LayoutProbe2() {}
}
