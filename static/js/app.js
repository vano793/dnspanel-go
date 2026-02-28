$(document).ready(function() {
    console.log('DNS Manager JS loaded');
    let currentDomainId = null;

    // Авторизация
    $('#loginForm').submit(function(e) {
        e.preventDefault();
        console.log('Login form submitted');
        
        $.ajax({
            url: '/api/login',
            method: 'POST',
            data: JSON.stringify({
                username: $('input[name="username"]').val(),
                password: $('input[name="password"]').val()
            }),
            contentType: 'application/json',
            dataType: 'json',
            xhrFields: { withCredentials: true },
            success: function(resp) {
                console.log('Login response:', resp);
                if (resp.success) {
                    window.location.href = '/';
                } else {
                    alert(resp.message || 'Неверный логин или пароль');
                }
            },
            error: function(xhr, status, error) {
                console.error('Login error:', xhr.responseText);
                alert('Ошибка соединения: ' + error);
            }
        });
    });

    // Выход (только один обработчик)
    $('#logoutBtn').click(function(e) {
        e.preventDefault();
        console.log('Logout clicked');
        $.ajax({
            url: '/api/logout',
            method: 'POST',
            xhrFields: { withCredentials: true },
            success: function(resp) {
                console.log('Logout success', resp);
                window.location.href = '/';
            },
            error: function(xhr) {
                console.error('Logout error', xhr);
                alert('Ошибка соединения: ' + xhr.statusText);
            }
        });
    });

    // Смена пароля
    $('#savePasswordBtn').click(function() {
        let current = $('input[name="current_password"]').val();
        let newPass = $('input[name="new_password"]').val();
        let confirm = $('input[name="confirm_password"]').val();

        if (!current || !newPass || !confirm) {
            alert('Заполните все поля');
            return;
        }

        $.ajax({
            url: '/api/user/change-password',
            method: 'POST',
            data: JSON.stringify({
                current_password: current,
                new_password: newPass,
                confirm_password: confirm
            }),
            contentType: 'application/json',
            xhrFields: { withCredentials: true },
            success: function(resp) {
                if (resp.success) {
                    alert('Пароль успешно изменен');
                    $('#changePasswordModal').modal('hide');
                    $('#changePasswordForm')[0].reset();
                } else {
                    alert(resp.message || 'Ошибка смены пароля');
                }
            },
            error: function(xhr) {
                alert('Ошибка соединения');
            }
        });
    });

    // Создание домена
    $('#saveDomainBtn').click(function() {
        console.log('Save domain clicked');
        
        const domain = $('input[name="name"]').val();
        const domainPattern = /^(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,})$/;
        
        if (!domainPattern.test(domain)) {
            alert('Некорректное имя домена');
            return;
        }

        let formData = {};

        if (window.userRole === 'admin') {
            formData = {
                name: domain,
                soa_email: $('input[name="soa_email"]').val(),
                soa_primary_ns: $('input[name="soa_primary_ns"]').val(),
                soa_refresh: parseInt($('input[name="soa_refresh"]').val()) || 7200,
                soa_retry: parseInt($('input[name="soa_retry"]').val()) || 3600,
                soa_expire: parseInt($('input[name="soa_expire"]').val()) || 1209600,
                soa_minimum: parseInt($('input[name="soa_minimum"]').val()) || 3600,
                create_ns: $('input[name="create_ns"]').is(':checked'),
                create_a: $('input[name="create_a"]').is(':checked')
            };
        } else {
            formData = {
                name: domain,
                soa_email: $('input[name="soa_email"]').val(),
                ip: $('input[name="ip"]').val()
            };
        }

        console.log('Sending data:', formData);

        $.ajax({
            url: '/api/domains',
            method: 'POST',
            data: JSON.stringify(formData),
            contentType: 'application/json',
            dataType: 'json',
            xhrFields: { withCredentials: true },
            success: function(resp) {
                console.log('Create domain response:', resp);
                if (resp.success) {
                    $('#domainModal').modal('hide');
                    location.reload();
                } else {
                    alert(resp.message || 'Ошибка создания домена');
                }
            },
            error: function(xhr, status, error) {
                console.error('Create domain error:', xhr.responseText);
                alert('Ошибка соединения: ' + error);
            }
        });
    });

    // Выбор домена
    $(document).on('click', '.domain-item', function() {
        $('.domain-item').removeClass('active');
        $(this).addClass('active');
        
        let id = $(this).data('id');
        currentDomainId = id;
        
        $('#addRecordBtn, #syncNSDBtn').show();
        $('#currentDomainTitle').html('<i class="bi bi-diagram-3 me-2"></i>' + $(this).find('.domain-name').text());
        
        $.ajax({
            url: '/api/domains/' + id + '/records',
            method: 'GET',
            xhrFields: { withCredentials: true },
            success: function(records) {
                renderRecordsTable(records);
            },
            error: function(xhr) {
                alert('Ошибка загрузки записей: ' + xhr.statusText);
            }
        });
    });

    // Удаление домена
    $(document).on('click', '.delete-domain', function(e) {
        e.stopPropagation();
        if (!confirm('Удалить домен и все его записи?')) return;
        
        let id = $(this).data('id');
        $.ajax({
            url: '/api/domains/' + id,
            method: 'DELETE',
            xhrFields: { withCredentials: true },
            success: function(resp) {
                if (resp.success) {
                    location.reload();
                } else {
                    alert('Ошибка: ' + (resp.message || 'неизвестная ошибка'));
                }
            },
            error: function(xhr) {
                alert('Ошибка соединения: ' + xhr.statusText);
            }
        });
    });

    // Добавление записи
    $('#addRecordBtn').click(function() {
        $('#recordForm')[0].reset();
        $('#recordId').val('');
        $('#recordDomainId').val(currentDomainId);
        $('#recordModalTitle').html('Добавить запись');
        $('#priorityField').hide();
        
        if (window.userRole !== 'admin') {
            $('#recordType option').show();
            if (!window.allowUsersCreateNS) {
                $('#recordType option[value="NS"]').hide();
            }
            if (!window.allowUsersCreateA) {
                $('#recordType option[value="A"]').hide();
            }
        }
        
        $('#recordModal').modal('show');
    });

    // Редактирование записи
    $(document).on('click', '.edit-record', function() {
        $('#recordId').val($(this).data('id'));
        $('#recordDomainId').val(currentDomainId);
        $('#recordType').val($(this).data('type'));
        $('#recordName').val($(this).data('name'));
        $('#recordContent').val($(this).data('content'));
        $('#recordPriority').val($(this).data('priority'));
        $('#recordTtl').val($(this).data('ttl'));
        
        $('#recordModalTitle').html('Редактировать запись');
        
        if (window.userRole !== 'admin') {
            $('#recordType').prop('disabled', true);
        } else {
            $('#recordType').prop('disabled', false);
        }
        
        $('#recordModal').modal('show');
    });

    // Сохранение записи
    $('#saveRecordBtn').click(function() {
        let method = $('#recordId').val() ? 'PUT' : 'POST';
        let url = $('#recordId').val() ? '/api/records/' + $('#recordId').val() : '/api/records';
        
        $.ajax({
            url: url,
            method: method,
            data: JSON.stringify({
                id: $('#recordId').val(),
                domain_id: $('#recordDomainId').val(),
                type: $('#recordType').val(),
                name: $('#recordName').val(),
                content: $('#recordContent').val(),
                priority: $('#recordPriority').val(),
                ttl: $('#recordTtl').val()
            }),
            contentType: 'application/json',
            xhrFields: { withCredentials: true },
            success: function(resp) {
                if (resp.success) {
                    $('#recordModal').modal('hide');
                    refreshRecords();
                } else {
                    alert(resp.message || 'Ошибка сохранения');
                }
            },
            error: function(xhr) {
                alert('Ошибка соединения: ' + xhr.statusText);
            }
        });
    });

    // Удаление записи
    $(document).on('click', '.delete-record', function() {
        if (!confirm('Удалить запись?')) return;
        
        let id = $(this).data('id');
        $.ajax({
            url: '/api/records/' + id,
            method: 'DELETE',
            xhrFields: { withCredentials: true },
            success: function(resp) {
                if (resp.success) {
                    refreshRecords();
                } else {
                    alert(resp.message || 'Ошибка удаления');
                }
            },
            error: function(xhr) {
                alert('Ошибка соединения: ' + xhr.statusText);
            }
        });
    });

    // Синхронизация NSD
    $('#syncNSDBtn').click(function() {
        var btn = $(this);
        btn.prop('disabled', true).html('<span class="spinner-border spinner-border-sm me-1"></span>Синхр...');
        
        $.ajax({
            url: '/api/nsd/sync/' + currentDomainId,
            method: 'POST',
            xhrFields: { withCredentials: true },
            complete: function() {
                btn.prop('disabled', false).html('Синхр. NSD');
            },
            success: function(resp) {
                if (resp.success) {
                    alert('NSD успешно синхронизирован');
                } else {
                    alert('Ошибка: ' + (resp.message || 'неизвестная ошибка'));
                }
            },
            error: function(xhr) {
                alert('Ошибка соединения');
            }
        });
    });

    // Показывать/скрывать поле приоритета
    $('#recordType').change(function() {
        if ($(this).val() === 'MX') {
            $('#priorityField').show();
        } else {
            $('#priorityField').hide();
        }
    });

    function refreshRecords() {
        $.ajax({
            url: '/api/domains/' + currentDomainId + '/records',
            method: 'GET',
            xhrFields: { withCredentials: true },
            success: function(records) {
                renderRecordsTable(records);
            },
            error: function(xhr) {
                alert('Ошибка загрузки записей');
            }
        });
    }

    function renderRecordsTable(records) {
        let html = '<div class="table-responsive"><table class="table table-hover"><thead><tr><th>Имя</th><th>TTL</th><th>Тип</th><th>Значение</th><th>Приоритет</th><th>Действия</th></tr></thead><tbody>';
        
        records.forEach(function(r) {
            let badgeClass = 'primary';
            if (r.Type === 'SOA') badgeClass = 'secondary';
            else if (r.Type === 'NS') badgeClass = 'info';
            else if (r.Type === 'MX') badgeClass = 'warning';
            
            html += '<tr>';
            html += '<td>' + (r.Name || '@') + '</td>';
            html += '<td>' + r.TTL + '</td>';
            html += '<td><span class="badge bg-' + badgeClass + '">' + r.Type + '</span></td>';
            html += '<td>' + (r.Content || '') + '</td>';
            html += '<td>' + (r.Priority || '-') + '</td>';
            html += '<td>';
            
            if (r.Type !== 'SOA') {
                html += '<button class="btn btn-sm btn-outline-primary edit-record me-1" data-id="' + r.ID + '" data-type="' + r.Type + '" data-name="' + r.Name + '" data-content="' + r.Content + '" data-priority="' + r.Priority + '" data-ttl="' + r.TTL + '"><i class="bi bi-pencil"></i></button>';
                html += '<button class="btn btn-sm btn-outline-danger delete-record" data-id="' + r.ID + '"><i class="bi bi-trash"></i></button>';
            } else {
                html += '<span class="text-muted"><i class="bi bi-lock"></i> SOA</span>';
            }
            
            html += '</td></tr>';
        });
        
        if (records.length === 0) {
            html += '<tr><td colspan="6" class="text-center text-muted py-4">Нет записей</td></tr>';
        }
        
        html += '</tbody></table></div>';
        $('#domainContent').html(html);
    }
});
