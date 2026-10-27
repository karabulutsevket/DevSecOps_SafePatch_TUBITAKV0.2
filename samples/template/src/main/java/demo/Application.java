package demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import java.util.Map;

@SpringBootApplication
@RestController
public class Application {
    private final DemoService service = new DemoService();
    public static void main(String[] args) { SpringApplication.run(Application.class, args); }
    @GetMapping("/health")
    public Map<String, String> health() { return Map.of("status", "ok", "scope", "synthetic-local-staging"); }
    @GetMapping("/lookup")
    public Map<String, String> lookup(@RequestParam String input) throws Exception {
        return Map.of("result", service.lookup(input));
    }
}
