SELECT *
FROM {% if prod %}production{% else %}development{% endif %}.orders