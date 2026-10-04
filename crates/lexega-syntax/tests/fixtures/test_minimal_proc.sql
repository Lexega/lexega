CREATE PROCEDURE test()
RETURNS VARCHAR
LANGUAGE SQL
AS
$$
BEGIN
    RETURN 'x';
END; /* after semi */ -- line after semi
$$ /* after dollar */ ; -- final
