package org.apache.hive.service.auth.ldap;

import org.apache.hadoop.hive.conf.HiveConf;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import javax.naming.NamingException;
import javax.security.sasl.AuthenticationException;

import java.util.Collections;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class TestPatternFilter {

    private FilterFactory factory;
    private HiveConf conf;

    @Mock
    private DirSearch search;

    @Before
    public void setup() {
        conf = new HiveConf();
        factory = new PatternFilterFactory();
    }

    @Test
    public void testFactory() {
        conf.unset(HiveConf.ConfVars.HIVE_SERVER2_PLAIN_LDAP_USE_PATTERN_FILTER.varname);
        assertNull(factory.getInstance(conf));

        conf.setBoolVar(HiveConf.ConfVars.HIVE_SERVER2_PLAIN_LDAP_USE_PATTERN_FILTER, false);
        assertNull(factory.getInstance(conf));

        conf.setBoolVar(HiveConf.ConfVars.HIVE_SERVER2_PLAIN_LDAP_USE_PATTERN_FILTER, true);
        assertNotNull(factory.getInstance(conf));
    }

    @Test
    public void testApplyPositive() throws AuthenticationException, NamingException {
        conf.setBoolVar(HiveConf.ConfVars.HIVE_SERVER2_PLAIN_LDAP_USE_PATTERN_FILTER, true);
        conf.setVar(HiveConf.ConfVars.HIVE_SERVER2_PLAIN_LDAP_USERDNPATTERN,
                "sAMAccountname=%s,OU=ldap_ou,DC=example,DC=com:sAMAccountname=%s,OU=hive_ou,DC=example,DC=com");
        conf.setVar(HiveConf.ConfVars.HIVE_SERVER2_PLAIN_LDAP_GROUPDNPATTERN,
                "CN=%s,OU=ldap_ou,DC=example,DC=com:CN=%s,OU=hive_ou,DC=example,DC=com");
        when(search.findUserDn(eq("User1")))
                .thenReturn("CN=User1,OU=ldap_ou,DC=example,DC=com");
        when(search.findUserDn(eq("User2")))
                .thenReturn("CN=User2,OU=hive_ou,DC=example,DC=com");

        when(search.findUserDn(eq("User3")))
                .thenReturn("CN=User3,OU=hive_test_ou,DC=example,DC=com");
        when(search.findGroupsForUser("CN=User3,OU=hive_test_ou,DC=example,DC=com"))
                .thenReturn(Collections.singletonList("CN=group1,OU=ldap_ou,DC=example,DC=com"));

        when(search.findUserDn(eq("User4")))
                .thenReturn("CN=User4,OU=hive_test_ou,DC=example,DC=com");
        when(search.findGroupsForUser("CN=User4,OU=hive_test_ou,DC=example,DC=com"))
                .thenReturn(Collections.singletonList("CN=group2,OU=hive_ou,DC=example,DC=com"));

        Filter filter = factory.getInstance(conf);
        filter.apply(search, "User1");
        filter.apply(search, "User2");
        filter.apply(search, "User3");
        filter.apply(search, "User4");
    }

    @Test(expected = AuthenticationException.class)
    public void testApplyNegative() throws AuthenticationException, NamingException {
        conf.setBoolVar(HiveConf.ConfVars.HIVE_SERVER2_PLAIN_LDAP_USE_PATTERN_FILTER, true);
        conf.setVar(HiveConf.ConfVars.HIVE_SERVER2_PLAIN_LDAP_USERDNPATTERN,
                "sAMAccountname=%s,OU=ldap_ou,DC=example,DC=com:sAMAccountname=%s,OU=hive_ou,DC=example,DC=com");
        conf.setVar(HiveConf.ConfVars.HIVE_SERVER2_PLAIN_LDAP_GROUPDNPATTERN,
                "CN=%s,OU=ldap_ou,DC=example,DC=com:CN=%s,OU=hive_ou,DC=example,DC=com");

        when(search.findUserDn(eq("User2")))
                .thenReturn("CN=User2,OU=hive_test_ou,DC=example,DC=com");
        Filter filter = factory.getInstance(conf);
        filter.apply(search, "User1");
        filter.apply(search, "User2");
    }
}
