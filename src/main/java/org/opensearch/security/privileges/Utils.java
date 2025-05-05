package org.opensearch.security.privileges;

import org.opensearch.action.bulk.BulkAction;
import org.opensearch.action.get.MultiGetAction;
import org.opensearch.action.search.MultiSearchAction;
import org.opensearch.action.search.SearchScrollAction;
import org.opensearch.action.termvectors.MultiTermVectorsAction;
import org.opensearch.index.reindex.ReindexAction;
import org.opensearch.script.mustache.RenderSearchTemplateAction;

public class Utils {
    public static boolean isClusterPerm(String action0) {
        return (action0.startsWith("cluster:")
                || action0.startsWith("indices:admin/template/")
                || action0.startsWith("indices:admin/index_template/")
                || action0.startsWith(SearchScrollAction.NAME)
                || (action0.equals(BulkAction.NAME))
                || (action0.equals(MultiGetAction.NAME))
                || (action0.startsWith(MultiSearchAction.NAME))
                || (action0.equals(MultiTermVectorsAction.NAME))
                || (action0.equals(ReindexAction.NAME))
                || (action0.equals(RenderSearchTemplateAction.NAME)));
    }
}
