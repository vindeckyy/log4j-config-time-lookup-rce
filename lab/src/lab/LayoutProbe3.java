package lab;

import java.util.Collections;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.core.impl.Log4jLogEvent;
import org.apache.logging.log4j.core.Appender;
import org.apache.logging.log4j.core.Layout;
import org.apache.logging.log4j.core.layout.PatternLayout;
import org.apache.logging.log4j.message.SimpleMessage;
import org.apache.logging.log4j.util.SortedArrayStringMap;

/** Is the layout doing more than one substitutor call? */
public final class LayoutProbe3 {

    public static void main(final String[] args) {
        final LoggerContext ctx = LoggerContext.getContext(false);
        final Configuration config = ctx.getConfiguration();
        System.out.println("config = " + config.getClass().getSimpleName());

        final Log4jLogEvent event = Log4jLogEvent.newBuilder()
                .setLoggerName("probe")
                .setLevel(Level.INFO)
                .setMessage(new SimpleMessage("hello"))
                .setContextData(new SortedArrayStringMap(Collections.singletonMap("ua", "v=${env:HOME}")))
                .build();

        final Appender appender = config.getAppender("Console");
        final Layout layout = appender == null ? null : appender.getLayout();
        System.out.println("config layout              = "
                + (layout == null ? "<none>" : String.valueOf(layout.toSerializable(event)).trim()));

        final PatternLayout bound = PatternLayout.newBuilder()
                .withConfiguration(config)
                .withPattern("CTX=${ctx:ua}")
                .build();
        System.out.println("bound PatternLayout        = " + bound.toSerializable(event).trim());

        System.out.println("subst.replace(bare)        = "
                + config.getStrSubstitutor().replace(event, "${ctx:ua}"));
        System.out.println("subst.replace(with text)   = "
                + config.getStrSubstitutor().replace(event, "CTX=${ctx:ua}"));
    }

    private LayoutProbe3() {}
}
