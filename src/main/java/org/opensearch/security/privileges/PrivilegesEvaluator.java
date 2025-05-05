package org.opensearch.security.privileges;

import java.util.List;
import java.util.Map;
import java.util.Set;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.bulk.BulkAction;
import org.opensearch.action.get.MultiGetAction;
import org.opensearch.action.search.MultiSearchAction;
import org.opensearch.action.search.SearchScrollAction;
import org.opensearch.action.termvectors.MultiTermVectorsAction;
import org.opensearch.core.common.transport.TransportAddress;
import org.opensearch.index.reindex.ReindexAction;
import org.opensearch.script.mustache.RenderSearchTemplateAction;
import org.opensearch.security.securityconf.impl.DashboardSignInOption;
import org.opensearch.security.user.User;
import org.opensearch.tasks.Task;

public interface PrivilegesEvaluator {

    boolean hasRestAdminPermissions(final User user, final TransportAddress remoteAddress, final String permission);

    boolean isInitialized();

    PrivilegesEvaluationContext createContext(User user, String action);

    PrivilegesEvaluationContext createContext(User user, String action0, ActionRequest request, Task task, Set<String> injectedRoles);

    PrivilegesEvaluatorResponse evaluate(PrivilegesEvaluationContext context);

    Set<String> mapRoles(final User user, final TransportAddress caller);

    Map<String, Boolean> mapTenants(final User user, Set<String> roles);

    Set<String> getAllConfiguredTenantNames();

    boolean multitenancyEnabled();

    boolean privateTenantEnabled();

    String dashboardsDefaultTenant();

    boolean notFailOnForbiddenEnabled();

    String dashboardsIndex();

    String dashboardsServerUsername();

    String dashboardsOpenSearchRole();

    List<DashboardSignInOption> getSignInOptions();

    PrivilegesEvaluatorResponse hasExplicitIndexPrivilege(PrivilegesEvaluationContext context, Set<String> actions, String index);

    void updatePluginToClusterActions(String pluginIdentifier, Set<String> clusterActions);

    PrivilegesEvaluatorResponse hasAnyClusterPrivilege(PrivilegesEvaluationContext context, Set<String> actions);
}
