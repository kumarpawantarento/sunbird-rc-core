<html>
<body>
    <p><H3>Hi</H3></p>

    <p>Please find below list of bulk user creation</p>

    <div>
        <#if succeedUsers?has_content>
            <br>
            <div><h3>Succeed User Details</h3></div>

            <table border="1" cellspacing="0" cellpadding="5">
                <tr>
                    <th>Username</th>
                    <th>Role</th>
                    <th>Remark</th>
                </tr>
                <#list succeedUsers as succeedUser>
                    <tr>
                        <td>${succeedUser.email} </td>
                        <td>${succeedUser.roleName} </td>
                        <td>${succeedUser.status} </td>
                    </tr>
                </#list>
            </table>
        </#if>
    </div>

    <div>
        <#if failedUsers?has_content>
            <br>
            <div><h3>Failed User Details</h3></div>

            <table border="1" cellspacing="0" cellpadding="5">
                <tr>
                    <th>Username</th>
                    <th>Role</th>
                    <th>Remark</th>
                </tr>
                <#list failedUsers as failedUser>
                <tr>
                    <td>${failedUser.email} </td>
                    <td>${failedUser.roleName} </td>
                    <td>${failedUser.status} </td>
                </tr>
                </#list>
            </table>
        </#if>
    </div>

    <p>Regards,</p>
    <p>${signature}</p>
</body>
</html>
