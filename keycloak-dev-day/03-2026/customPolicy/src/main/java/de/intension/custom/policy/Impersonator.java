package de.intension.custom.policy;

import org.checkerframework.checker.nullness.qual.NonNull;
import org.jboss.logging.Logger;

import java.text.SimpleDateFormat;
import java.util.Date;

public record Impersonator(String email, Date startDate, Date endDate) {
    private static final Logger logger = Logger.getLogger(Impersonator.class);
    public Impersonator {
        if (startDate == null || endDate == null) {
            throw new IllegalArgumentException("startDate and endDate cannot be null");
        }
        if (startDate.after(endDate)) {
            throw new IllegalArgumentException("startDate must be before endDate");
        }
    }

    @Override
    public @NonNull String toString() {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
        return email + ";" + sdf.format(startDate) + ";" + sdf.format(endDate);
    }

    public boolean isBetweenTimeFrame(Date date) {
        logger.infof("Checking if %s is between %s and %s", date, startDate, endDate);
        return startDate.before(date) && endDate.after(date)
            || startDate.equals(date) || endDate.equals(date);
    }
}
