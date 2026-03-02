package de.intension.custom.policy;

import org.checkerframework.checker.nullness.qual.NonNull;

import java.text.SimpleDateFormat;
import java.util.Date;

public record Impersonater(String email, Date startDate, Date endDate) {
    public Impersonater {
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
}
