package org.zerock.j09;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

@SpringBootApplication
@EnableJpaAuditing
public class J09Application {

    public static void main(String[] args) {
        SpringApplication.run(J09Application.class, args);
    }

}
