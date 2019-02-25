package com.lingyejun.authenticator;

import com.lingyejun.authenticator.tick.TickAuthenticator;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;


/**
 * @Author: lingyejun
 * @Date: 2019/2/19
 * @Describe: 
 * @Modified By:
 */
public class TickAuthenticatorTest {

    @Test
    public void rfc6238Test(){

        TickAuthenticator ta = new TickAuthenticator();
        byte[] key = null;
        assertEquals(ta.generateAuthCode(key,59L/30),967832);
    }
}
