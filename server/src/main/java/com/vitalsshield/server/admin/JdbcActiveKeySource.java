package com.vitalsshield.server.admin;

import java.util.List;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

@Component
public class JdbcActiveKeySource implements ActiveKeySource {

    private final JdbcTemplate jdbc;

    public JdbcActiveKeySource(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @Override
    public List<ActiveKey> load() {
        return jdbc.query("SELECT purpose::text, kms_key_id FROM kms_keys WHERE status = 'ACTIVE' ORDER BY purpose",
                (rs, i) -> new ActiveKey(rs.getString(1), rs.getString(2)));
    }
}
