-- Test CST-based Jinja formatting
{% if target.name == 'prod' %}
-- comment after if
SELECT *
FROM users
WHERE active = true;
{% else %}
/* comment after else */ SELECT *
FROM users_staging
WHERE active = true; /* trailing */ 
{% endif %} -- comment after endif
