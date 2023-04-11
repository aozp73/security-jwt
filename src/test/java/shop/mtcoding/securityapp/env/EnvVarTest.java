package shop.mtcoding.securityapp.env;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;

public class EnvVarTest {

    @Test
    public void secret_test() {
        String key = System.getenv("HS512_SECRET");
        System.out.println("테스트 : " + key);
    }
}
