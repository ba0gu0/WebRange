$('.dropify').dropify({
    messages: {
        'default': 'Drag and drop a file here or click',
        'replace': 'Drag and drop or click to replace',
        'remove': 'Remove',
        'error': 'Ooops, something wrong appended.'
    },
    error: {
        'fileSize': 'The file size is too big (1M max).'
    }
});

$('#up-type').change(function () {
    if ($(this).val() == 'json') {
        $('.uploadjson').css('display', '');
        $('.uploadfile').css('display', 'none');
    } else if ($(this).val() == 'file') {
        $('.uploadjson').css('display', 'none');
        $('.uploadfile').css('display', '');
    } else {
        $('.uploadjson').css('display', 'none');
        $('.uploadfile').css('display', 'none');
    }
});



$('#add').click(function () {
    name = $('#env-name').val();
    info = $('#env-info').val();
    author = $('#env-author').val();
    risk = $('#env-risk').val();
    info = $('#env-info').val();
    tags = $('#env-tags').val();
    hub = $('#env-hub').val();
    type = $('#env-type').val();
    port = $('#env-port').val();
    flag = $('#env-flag').val();
    path = $('#env-fileupload').val();
    syspassjson = $('#env-syspass-json').val();
    syspassfile = $('#env-syspass-file').val();
    filename = path.substring(path.lastIndexOf('\\')).split('.')[0];
    isupload = $('#env-isupload').val();
    $.ajaxFileUpload({
        url: "/add_images",
        secureuri: false,
        type: "POST",
        data: {
            name: name,
            info: info,
            isupload: isupload,
            type: type,
            flag: flag,
            author: author,
            risk: risk,
            tags: tags,
            hub: hub,
            port: port,
            syspassjson: syspassjson,
            syspassfile: syspassfile
        },
        dataType: "json",
        fileElementId: "env-fileupload",
        success: function (e) {
        },
        error: function (e) {
            if (e.responseText == 'success') {
                swal("新增成功,正在后台进行下载！", '', "success");
                $('.confirm').click(function () {
                    $('#close').click();
                    location.reload();
                });

            } else {
                swal("新增失败", "请检查数据是否完整或是否存在特殊字符!", "error")
            }
        }
    });

});

