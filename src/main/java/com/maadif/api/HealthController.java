package com.maadif.api;

import io.javalin.http.Context;
import java.util.Map;

public class HealthController {

    public static void health(Context ctx) {
        ctx.json(Map.of(
            "status", "ok",
            "service", "maadif",
            "version", "1.0.0"
        ));
    }
}
