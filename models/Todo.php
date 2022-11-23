<?php

class Todo
{
    // DB stuff
    /**
     * @var PDO
     */
    private $conn;
    private $table = 'todo';

    // Todo Properties
    public $id;
    public $item;
    public $sort;
    public $todoStatu;
    public $addDate;
    public $completDate;
    public $from;
    public $to;
    public $PosFrom;
    public $PosTo;

    // Constructor with DB
    public function __construct($db)
    {
        $this->conn = $db;
    }

    // Get Uncompleted tasks
    public function getUncompleted()
    {
        // Create query
        $query = 'SELECT * FROM ' . $this->table . ' WHERE  todoStatu=1 ORDER BY sort ASC  ';

        // Prepare statement
        $stmt = $this->conn->prepare($query);

        // Execute query
        $stmt->execute();

        return $stmt;
    }

    public function getAll()
    {
        // Create query
        $query = 'SELECT * FROM ' . $this->table . ' ORDER BY sort ASC  ';

        // Prepare statement
        $stmt = $this->conn->prepare($query);

        // Execute query
        $stmt->execute();

        return $stmt;
    }

    // Get Completed tasks
    public function getCompleted()
    {
        // Create query
        $query = 'SELECT * FROM ' . $this->table . ' WHERE  todoStatu=2  ORDER BY sort ASC  ';

        // Prepare statement
        $stmt = $this->conn->prepare($query);

        // Execute query
        $stmt->execute();

        return $stmt;
    }

    // Get Single Task
    public function read_one()
    {
        // Create query
        $query = 'SELECT  * FROM ' . $this->table . '  WHERE id = ? LIMIT 0,1';

        // Prepare statement
        $stmt = $this->conn->prepare($query);

        $this->id = filter_var($this->id, FILTER_SANITIZE_NUMBER_INT);

        // Bind ID
        $stmt->bindParam(1, $this->id);

        // Execute query
        $stmt->execute();

        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        // Set properties
        $this->item = $row['item'];
        $this->sort = $row['sort'];
        $this->todoStatu = $row['todoStatu'];
        $this->addDate = $row['addDate'];
        $this->completDate = $row['completDate'];
    }

    // Create Task
    public function create()
    {
        // Create query
        if (!empty($this->item)) {
            $query = 'UPDATE ' . $this->table . ' SET sort = sort+1 WHERE todoStatu = 1';

            // Prepare statement
            $stmtUpdate = $this->conn->prepare($query);

            // Execute query
            if ($stmtUpdate->execute()) {
                // Create query
                $query = 'INSERT INTO ' . $this->table . ' SET item = :item, todoStatu = :todoStatu, sort = :sort';

                // Prepare statement
                $stmt = $this->conn->prepare($query);

                // Clean data
                $this->item = filter_var($this->item, FILTER_SANITIZE_STRING);
                $this->sort = filter_var(1, FILTER_SANITIZE_NUMBER_INT);
                $this->todoStatu = filter_var(1, FILTER_SANITIZE_NUMBER_INT);

                // Bind data
                $stmt->bindParam(':item', $this->item);
                $stmt->bindParam(':sort', $this->sort);
                $stmt->bindParam(':todoStatu', $this->todoStatu);
                if ($stmt->execute()) {
                    return true;
                }
            }
        }


        return false;
    }


    function encodeToBase64($str)
    {
        return rtrim(strtr(base64_encode($str), '+/', '-_'), '=');
    }

    // Authenticate
    public function auth($headers, $payload, $secret)
    {
        $headers_encoded = $this->encodeToBase64(json_encode($headers));

        $payload_encoded = $this->encodeToBase64(json_encode($payload));

        $signature = hash_hmac('SHA256', "$headers_encoded.$payload_encoded", $secret, true);
        $signature_encoded = $this->encodeToBase64($signature);

        $jwt = "$headers_encoded.$payload_encoded.$signature_encoded";

        return $jwt;
    }

    public function is_jwt_valid($jwt, $secret)
    {
        // split the jwt
        $tokenParts = explode('.', $jwt); 
        $header = base64_decode($tokenParts[0]);
        $payload = base64_decode($tokenParts[1]);
        $signature_provided = $tokenParts[2];

        // check the expiration time - note this will cause an error if there is no 'exp' claim in the jwt
        $expiration = json_decode($payload)->exp;
        $is_token_expired = ($expiration - time()) < 0;

        // build a signature based on the header and payload using the secret
        $base64_url_header = $this->encodeToBase64($header);
        $base64_url_payload = $this->encodeToBase64($payload);
        $signature = hash_hmac('SHA256', $base64_url_header . "." . $base64_url_payload, $secret, true);
        $base64_url_signature = $this->encodeToBase64($signature);

        // verify it matches the signature provided in the jwt
        $is_signature_valid = ($base64_url_signature === $signature_provided);

        if ($is_token_expired || !$is_signature_valid) {
            return FALSE;
        } else {
            return TRUE;
        }
    }



    // Update Post
    public function update()
    {
        // Create query
        $query = 'UPDATE  ' . $this->table . ' SET item=:item WHERE id=:id';
        // Prepare statement
        $stmt = $this->conn->prepare($query);
        // Clean data
        $this->id = filter_var($this->id, FILTER_SANITIZE_NUMBER_INT);
        $this->item = filter_var($this->item, FILTER_SANITIZE_STRING);
        // Bind data
        $stmt->bindParam(':id', $this->id);
        $stmt->bindParam(':item', $this->item);

        // Execute query
        if ($stmt->execute()) {
            return true;
        }


        return false;
    }

    // Delete Post
    public function delete()
    {
        $query = 'SELECT item FROM ' . $this->table . ' WHERE id = :id';

        // Prepare statement
        $stmtFind = $this->conn->prepare($query);

        // Clean data
        $this->id = filter_var($this->id, FILTER_SANITIZE_NUMBER_INT);
        // Bind data
        $stmtFind->bindParam(':id', $this->id);
        // Execute query
        if ($stmtFind->execute() and $stmtFind->rowCount() > 0) {
            // Create query
            $query = 'UPDATE  ' . $this->table . ' SET sort = sort - 1 WHERE todoStatu = :todoStatu AND sort > :sort ';

            // Prepare statement
            $stmtUpdate = $this->conn->prepare($query);

            // Clean data
            $this->sort = filter_var($this->sort, FILTER_SANITIZE_NUMBER_INT);
            $this->todoStatu = filter_var($this->todoStatu, FILTER_SANITIZE_NUMBER_INT);

            // Bind data
            $stmtUpdate->bindParam(':sort', $this->sort);
            $stmtUpdate->bindParam(':todoStatu', $this->todoStatu);

            // Execute query
            if ($stmtUpdate->execute()) {
                $query = 'DELETE FROM ' . $this->table . ' WHERE id = :id';

                // Prepare statement
                $stmt = $this->conn->prepare($query);

                // Clean data
                $this->id = filter_var($this->id, FILTER_SANITIZE_NUMBER_INT);
                // Bind data
                $stmt->bindParam(':id', $this->id);

                // Execute query
                if ($stmt->execute()) {
                    return true;
                }
            }
        }


        return false;
    }


    public function markAsCompleted()
    {
        $query = 'UPDATE ' . $this->table . ' SET sort = sort +1 WHERE todoStatu= :todoStatu';
        // Prepare statement
        $stmt = $this->conn->prepare($query);
        // Clean data
        $this->todoStatu = filter_var($this->todoStatu, FILTER_SANITIZE_NUMBER_INT);
        // Bind data
        $stmt->bindParam(':todoStatu', $this->todoStatu);
        if ($stmt->execute()) {
            // Create query
            $query = 'UPDATE ' . $this->table . ' SET sort = sort - 1 WHERE sort > :sort and todoStatu = 1';
            // Prepare statement
            $stmt = $this->conn->prepare($query);
            // Clean data
            $this->sort = filter_var($this->sort, FILTER_SANITIZE_NUMBER_INT);
            // Bind data
            $stmt->bindParam(':sort', $this->sort);
            if ($stmt->execute()) {
                $query = 'UPDATE  ' . $this->table . ' SET sort=1,todoStatu=:todoStatu,completDate=:completDate WHERE id=:id';
                // Prepare statement
                $stmt = $this->conn->prepare($query);
                // Clean data
                $this->id = filter_var($this->id, FILTER_SANITIZE_NUMBER_INT);
                $this->todoStatu = filter_var($this->todoStatu, FILTER_SANITIZE_NUMBER_INT);
                $this->completDate = date("Y-m-d H:i:s");
                // Bind data
                $stmt->bindParam(':id', $this->id);
                $stmt->bindParam(':todoStatu', $this->todoStatu);
                $stmt->bindParam(':completDate', $this->completDate);
                if ($stmt->execute()) {
                    return true;
                }
            }
        }


        return false;
    }

    public function markAsUncompleted()
    {
        $query = 'UPDATE ' . $this->table . ' SET sort = sort +1 WHERE todoStatu= :todoStatu';
        // Prepare statement
        $stmt = $this->conn->prepare($query);
        // Clean data
        $this->todoStatu = filter_var($this->todoStatu, FILTER_SANITIZE_NUMBER_INT);
        // Bind data
        $stmt->bindParam(':todoStatu', $this->todoStatu);
        if ($stmt->execute()) {
            // Create query
            $query = 'UPDATE ' . $this->table . ' SET sort = sort - 1 WHERE sort > :sort and todoStatu = 2';
            // Prepare statement
            $stmt = $this->conn->prepare($query);
            // Clean data
            $this->sort = filter_var($this->sort, FILTER_SANITIZE_NUMBER_INT);
            // Bind data
            $stmt->bindParam(':sort', $this->sort);
            if ($stmt->execute()) {
                $query = 'UPDATE  ' . $this->table . ' SET sort=1,todoStatu=:todoStatu,completDate=:completDate WHERE id=:id';
                // Prepare statement
                $stmt = $this->conn->prepare($query);
                // Clean data
                $this->id = filter_var($this->id, FILTER_SANITIZE_NUMBER_INT);
                $this->todoStatu = filter_var($this->todoStatu, FILTER_SANITIZE_NUMBER_INT);
                $this->completDate = '0000-00-00 00:00:00';
                // Bind data
                $stmt->bindParam(':id', $this->id);
                $stmt->bindParam(':todoStatu', $this->todoStatu);
                $stmt->bindParam(':completDate', $this->completDate);
                if ($stmt->execute()) {
                    return true;
                }
            }
        }

        return false;
    }

    public function Sort()
    {
        $query = 'UPDATE ' . $this->table . ' SET sort = CASE id WHEN :from THEN  :posFrom
                  WHEN :to THEN :posTo  END  WHERE id in (:from, :to)';
        // Prepare statement
        $stmt = $this->conn->prepare($query);
        // Clean data
        $this->from = filter_var($this->from, FILTER_SANITIZE_NUMBER_INT);
        $this->to = filter_var($this->to, FILTER_SANITIZE_NUMBER_INT);
        $this->PosFrom = filter_var($this->PosFrom, FILTER_SANITIZE_NUMBER_INT);
        $this->PosTo = filter_var($this->PosTo, FILTER_SANITIZE_NUMBER_INT);
        // Bind data
        $stmt->bindParam(':from', $this->from);
        $stmt->bindParam(':to', $this->to);
        $stmt->bindParam(':posFrom', $this->PosFrom);
        $stmt->bindParam(':posTo', $this->PosTo);
        if ($stmt->execute()) {
            return true;
        }
        return false;
    }
}
