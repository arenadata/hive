package org.apache.hive.service.auth.ldap;

import org.apache.hadoop.hive.conf.HiveConf;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.sasl.AuthenticationException;
import java.util.List;

public class PatternFilterFactory implements FilterFactory {


    public static void main(String[] args) {
        System.currentTimeMillis();
    }

    @Override
    public Filter getInstance(HiveConf conf) {
        final List<String> userPatterns = LdapUtils.parseDnPatterns(conf,
                HiveConf.ConfVars.HIVE_SERVER2_PLAIN_LDAP_USERDNPATTERN);
        final List<String> groupBases = LdapUtils.patternsToBaseDns(LdapUtils.parseDnPatterns(conf,
                HiveConf.ConfVars.HIVE_SERVER2_PLAIN_LDAP_GROUPDNPATTERN));
        final List<String> userBases = LdapUtils.patternsToBaseDns(userPatterns);

        return new PatternFilter(userBases, groupBases);
    }


    private static final class PatternFilter implements Filter {

        private static final Logger LOG = LoggerFactory.getLogger(PatternFilter.class);

        private final List<String> groupDnPattern;

        private final List<String> userDnPattern;

        public PatternFilter(List<String> groupDnPattern, List<String> userDnPattern) {
            this.groupDnPattern = groupDnPattern;
            this.userDnPattern = userDnPattern;
        }

        @Override
        public void apply(DirSearch client, String user) throws AuthenticationException {

            throw new AuthenticationException("Authentication failed: "
                    + "User not a member of specified list");
        }
    }
}
