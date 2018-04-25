
function getQueryString(name) {
    var reg = new RegExp("(^|&)" + name + "=([^&]*)(&|$)", "i");
    var r = window.location.search.substr(1).match(reg);
    if (r != null) return unescape(r[2]);
    return null;
}

function setCookie(c_name, value, expirehours) {
    var exdate = new Date();
    exdate.setHours(exdate.getHours() + expirehours);
    document.cookie = c_name + "=" + escape(value) +
        ((expirehours == null) ? "" : ";expires=" + exdate.toGMTString())
}

function getCookie(name) {
    var cookies = document.cookie.split(";");
    for (var i = 0; i < cookies.length; i++) {
        var cookie = cookies[i];
        var cookieStr = cookie.split("=");
        if (cookieStr && cookieStr[0].trim() == name) {
            return decodeURI(cookieStr[1]);
        }
    }
}


function delAllCookie() {
    var myDate = new Date();
    myDate.setTime(-1000);
    var data = document.cookie;
    var dataArray = data.split("; ");
    for (var i = 0; i < dataArray.length; i++) {
        var varName = dataArray[i].split("=");
        document.cookie = varName[0] + "=''; expires=" + myDate.toGMTString();
    }

}

/**
 * 更新url中的get请求
 *
 * @param    {string}  key     http get query key
 * @param    {string}  key     http get query value
 * @returns  url?key=value&key=value
 */
String.prototype.url_update_query = function(key, value) {
    if (key) {
        var re = new RegExp("([?&])" + key + "=.*?(&|$)", "i");
        var separator = this.indexOf('?') !== -1 ? "&" : "?";
        if (this.match(re)) {
            return this.replace(re, '$1' + key + "=" + value + '$2');
        }
        else {
            return this + separator + key + "=" + value;
        }
    }
    return this.toString();
}

/**
 * 更新url中的page参数
 *
 * @param    {string}  page    the number of page
 * @returns  url?page=1
 *
 * @author   ysrc
 */
String.prototype.url_add_Paginator = function(page) {
    if (page == undefined) {
        return this.toString();
    } 
    result = this.url_update_query("page", page);
    return result.toString();
}

/**
 * 跳转到下一页
 *
 * @author   ysrc
 */
function nextPage() {
    page = parseInt(getQueryString('page') == null ? 1 : getQueryString('page')) + 1;
    if (page > $('.pagination-split').children().length - 2) {
        alert('已到达末页');
    } else {
        location.replace(location.href.url_add_Paginator(page));
    }
}

function prePage() {
    page = parseInt(getQueryString('page') == null ? 1 : getQueryString('page')) - 1;
    if (page > 0) {
        oripage = page + 1;
        location.href = location.href.replace("page=" + oripage.toString(), "page=" + page.toString());
    } else {
        alert('已到达首页');
    }
}
function turnTo(page) {
    curPage = getQueryString('page');
    location.replace(location.href.url_add_Paginator(page));
}

