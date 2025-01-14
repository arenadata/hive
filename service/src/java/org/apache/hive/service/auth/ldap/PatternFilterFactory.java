package org.apache.hive.service.auth.ldap;

import org.apache.hadoop.hive.conf.HiveConf;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.sasl.AuthenticationException;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

public class PatternFilterFactory implements FilterFactory {

    @Override
    public Filter getInstance(HiveConf conf) {
        final boolean usePatternFilter = conf.getBoolVar(HiveConf.ConfVars.HIVE_SERVER2_PLAIN_LDAP_USE_PATTERN_FILTER);

        if (usePatternFilter) {
            final List<String> userPatterns = LdapUtils.parseDnPatterns(conf,
                    HiveConf.ConfVars.HIVE_SERVER2_PLAIN_LDAP_USERDNPATTERN);
            final List<String> groupBases = LdapUtils.patternsToBaseDns(LdapUtils.parseDnPatterns(conf,
                    HiveConf.ConfVars.HIVE_SERVER2_PLAIN_LDAP_GROUPDNPATTERN));
            final List<String> userBases = LdapUtils.patternsToBaseDns(userPatterns);
            return new PatternFilter(userBases, groupBases);
        } else {
            return null;
        }
    }


    private static final class PatternFilter implements Filter {

        private static final Logger LOG = LoggerFactory.getLogger(PatternFilter.class);

        private final List<String> userBases;
        private final List<String> groupBases;

        public PatternFilter(List<String> userBases, List<String> groupBases) {
            this.userBases = userBases;
            this.groupBases = groupBases;
        }

        @Override
        public void apply(DirSearch client, String user) throws AuthenticationException {
            LOG.info("Authenticating user '{}' using {}", user,
                    PatternFilter.class.getSimpleName());
            try {
                String userDn = client.findUserDn(user);
                String baseDn = LdapUtils.extractBaseDn(userDn);
                if (!userBases.contains(baseDn)) {
                    LOG.debug("{} does not contain user {} base DN {}",
                            String.join(":", userBases), userDn, baseDn);
                    List<String> userGroups = client.findGroupsForUser(userDn).stream()
                            .map(LdapUtils::extractBaseDn)
                            .collect(Collectors.toList());
                    Optional<String> intersectWithBaseGroupsCount = userGroups.stream()
                            .filter(groupBases::contains)
                            .findAny();
                    if (!intersectWithBaseGroupsCount.isPresent()) {
                        LOG.debug("{} is not a member of any group {}", userDn, String.join(":", groupBases));
                        throw new AuthenticationException(
                                String.format("Authentication failed: User %s with baseDn %s not a member of specified lists: %s ; %s",
                                        userDn, baseDn, String.join(":", userBases), String.join(":", groupBases)));
                    }
                }
                LOG.info("Authentication succeeded based on user-group pattern membership");
            } catch (Exception e) {
                throw new AuthenticationException(e.getMessage());
            }
        }
    }
}
