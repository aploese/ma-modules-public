<%--
    Copyright (C) 2014 Infinite Automation Systems Inc. All rights reserved.
    @author Matthew Lohbihler
--%><%@include file="/WEB-INF/tags/decl.tagf"%><%--
--%><%@taglib prefix="jviews" uri="/WEB-INF/modules/jspViews/jviews.tld" %><%--
--%><%@tag body-content="empty"%><%--
--%><%@attribute name="xid" required="true"%><%--
--%><%@attribute name="raw" type="java.lang.Boolean"%><%--
--%><%@attribute name="disabledValue" required="false"%><%--
--%><jviews:simplePoint xid="${xid}" raw="${raw}" disabledValue="${disabledValue}"/><%--
--%><span id="c${componentId}"></span>
