SELECT *
FROM {% if use_archive %}archive{% else %}current{% endif %}.{{ table_name }}